'use strict';

const express = require('express');
const axios = require('axios');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Config (fail-fast on missing required env in production)
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT) || 3000;
const PYTHON_ENGINE_URL =
    process.env.ENGINE_URL || 'http://127.0.0.1:8000/api/v1/analyze';
const ENGINE_TIMEOUT_MS = Number(process.env.ENGINE_TIMEOUT_MS) || 1500;
const ARKADA_TIMEOUT_MS = Number(process.env.ARKADA_TIMEOUT_MS) || 800;
const ARKADA_RANK_THRESHOLD = Number(process.env.ARKADA_RANK_THRESHOLD) || 50;
const MAX_BODY_BYTES = process.env.MAX_BODY_BYTES || '32kb';
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 60_000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 60; // per IP per window
const API_KEYS = (process.env.API_KEYS || '')
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean);
const IS_PROD = process.env.NODE_ENV === 'production';

if (IS_PROD && !process.env.ENGINE_URL) {
    // Refuse to silently call localhost in production.
    // eslint-disable-next-line no-console
    console.error('FATAL: ENGINE_URL must be set explicitly in production.');
    process.exit(1);
}
if (IS_PROD && API_KEYS.length === 0) {
    // eslint-disable-next-line no-console
    console.error('FATAL: API_KEYS must be set in production.');
    process.exit(1);
}

// ---------------------------------------------------------------------------
// Tiny structured logger (no extra deps)
// ---------------------------------------------------------------------------
const log = (level, msg, fields = {}) => {
    // eslint-disable-next-line no-console
    console.log(
        JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields })
    );
};

// ---------------------------------------------------------------------------
// Keep-alive HTTP agents for downstream calls
// ---------------------------------------------------------------------------
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 50 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 50 });
const engineClient = axios.create({
    baseURL: PYTHON_ENGINE_URL,
    timeout: ENGINE_TIMEOUT_MS,
    httpAgent,
    httpsAgent,
    // Treat any non-2xx as an error so we hit the catch path explicitly
    validateStatus: (s) => s >= 200 && s < 300,
});

// ---------------------------------------------------------------------------
// Naive per-IP rate limiter (in-memory; swap for Redis in multi-instance)
// ---------------------------------------------------------------------------
const rateBuckets = new Map(); // ip -> { count, resetAt }
const rateLimit = (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let bucket = rateBuckets.get(ip);
    if (!bucket || bucket.resetAt < now) {
        bucket = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
        rateBuckets.set(ip, bucket);
    }
    bucket.count += 1;
    if (bucket.count > RATE_LIMIT_MAX) {
        res.setHeader('Retry-After', Math.ceil((bucket.resetAt - now) / 1000));
        return res
            .status(429)
            .json({ status: 'rejected', reason: 'rate_limited' });
    }
    return next();
};

// Periodically prune stale buckets so the Map doesn't grow unbounded.
setInterval(() => {
    const now = Date.now();
    for (const [ip, b] of rateBuckets) {
        if (b.resetAt < now) rateBuckets.delete(ip);
    }
}, RATE_LIMIT_WINDOW_MS).unref();

// ---------------------------------------------------------------------------
// API-key auth (constant-time compare)
// ---------------------------------------------------------------------------
const requireApiKey = (req, res, next) => {
    // Allow unauthenticated calls only outside production AND when no keys configured.
    if (!IS_PROD && API_KEYS.length === 0) return next();

    const provided = req.get('x-api-key') || '';
    const providedBuf = Buffer.from(provided);
    const ok = API_KEYS.some((k) => {
        const kb = Buffer.from(k);
        return (
            kb.length === providedBuf.length &&
            crypto.timingSafeEqual(kb, providedBuf)
        );
    });
    if (!ok) {
        return res
            .status(401)
            .json({ status: 'rejected', reason: 'unauthorized' });
    }
    return next();
};

// ---------------------------------------------------------------------------
// Request ID middleware
// ---------------------------------------------------------------------------
const attachRequestId = (req, res, next) => {
    const incoming = req.get('x-request-id');
    req.id = incoming && /^[a-zA-Z0-9_-]{1,64}$/.test(incoming)
        ? incoming
        : crypto.randomUUID();
    res.setHeader('x-request-id', req.id);
    next();
};

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------
const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const MAX_FINGERPRINT_KEYS = 64;
const MAX_FINGERPRINT_STRING_LEN = 2048;

const isPlainObject = (v) =>
    v !== null && typeof v === 'object' && !Array.isArray(v);

const validateFingerprint = (fp) => {
    if (!isPlainObject(fp)) return 'fingerprint_must_be_object';
    const keys = Object.keys(fp);
    if (keys.length === 0) return 'fingerprint_empty';
    if (keys.length > MAX_FINGERPRINT_KEYS) return 'fingerprint_too_many_keys';
    for (const k of keys) {
        const v = fp[k];
        // Only allow primitives or shallow arrays of primitives — no nested objects.
        // This blocks prototype pollution payloads and keeps the schema flat.
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
            return 'fingerprint_forbidden_key';
        }
        if (Array.isArray(v)) {
            if (v.length > MAX_FINGERPRINT_KEYS) return 'fingerprint_array_too_long';
            for (const item of v) {
                if (item !== null && typeof item === 'object') {
                    return 'fingerprint_nested_object';
                }
                if (typeof item === 'string' && item.length > MAX_FINGERPRINT_STRING_LEN) {
                    return 'fingerprint_string_too_long';
                }
            }
        } else if (v !== null && typeof v === 'object') {
            return 'fingerprint_nested_object';
        } else if (typeof v === 'string' && v.length > MAX_FINGERPRINT_STRING_LEN) {
            return 'fingerprint_string_too_long';
        }
    }
    return null;
};

const validateVerifyBody = (body) => {
    if (!isPlainObject(body)) return 'body_must_be_object';
    const { walletAddress, fingerprint } = body;
    if (typeof walletAddress !== 'string') return 'walletAddress_required';
    if (!EVM_ADDRESS_RE.test(walletAddress)) return 'walletAddress_invalid';
    const fpErr = validateFingerprint(fingerprint);
    if (fpErr) return fpErr;
    return null;
};

// ---------------------------------------------------------------------------
// Arkada reputation client (mock — gated to non-prod)
// ---------------------------------------------------------------------------
const arkadaCache = new Map(); // address -> { value, expiresAt }
const ARKADA_CACHE_TTL_MS = 60_000;
const ARKADA_CACHE_MAX = 5_000;

const cacheGet = (addr) => {
    const hit = arkadaCache.get(addr);
    if (!hit) return null;
    if (hit.expiresAt < Date.now()) {
        arkadaCache.delete(addr);
        return null;
    }
    return hit.value;
};
const cacheSet = (addr, value) => {
    if (arkadaCache.size >= ARKADA_CACHE_MAX) {
        // Drop the oldest entry (Maps preserve insertion order)
        const firstKey = arkadaCache.keys().next().value;
        if (firstKey !== undefined) arkadaCache.delete(firstKey);
    }
    arkadaCache.set(addr, { value, expiresAt: Date.now() + ARKADA_CACHE_TTL_MS });
};

const checkArkadaRank = async (walletAddress, { signal } = {}) => {
    const cached = cacheGet(walletAddress);
    if (cached) return cached;

    // --- MOCK BLOCK: only active outside production ---
    if (!IS_PROD) {
        const latency = Math.floor(Math.random() * 100) + 50;
        await new Promise((resolve, reject) => {
            const t = setTimeout(resolve, latency);
            if (signal) {
                signal.addEventListener('abort', () => {
                    clearTimeout(t);
                    reject(new Error('aborted'));
                }, { once: true });
            }
        });
        // NOTE: the prior `0xTRUST` bypass has been REMOVED. Mocks must never
        // grant trust based on attacker-controlled input shape.
        const value = { isVerified: false, rank: 12, source: 'mock' };
        cacheSet(walletAddress, value);
        return value;
    }

    // --- PROD BLOCK: real client must be wired here ---
    throw new Error('arkada_client_not_configured');
};

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS) || 0);
app.use(express.json({ limit: MAX_BODY_BYTES }));
app.use(attachRequestId);

// Body-parser errors (e.g. payload too large, malformed JSON)
app.use((err, req, res, next) => {
    if (err && err.type === 'entity.too.large') {
        return res.status(413).json({ status: 'rejected', reason: 'payload_too_large' });
    }
    if (err && err.type === 'entity.parse.failed') {
        return res.status(400).json({ status: 'rejected', reason: 'malformed_json' });
    }
    return next(err);
});

// Health endpoints
app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/ready', async (_req, res) => {
    // Light readiness check — does NOT call the engine to avoid amplification.
    res.json({ ok: true, engine: PYTHON_ENGINE_URL });
});

// Main verify route
app.post('/api/verify', rateLimit, requireApiKey, async (req, res) => {
    const reqId = req.id;
    const startedAt = Date.now();

    // 1) Validate input BEFORE any downstream call.
    const validationError = validateVerifyBody(req.body);
    if (validationError) {
        log('warn', 'verify.invalid_input', { reqId, code: validationError });
        return res.status(400).json({
            status: 'rejected',
            reason: 'invalid_input',
            ref: reqId,
        });
    }

    const { walletAddress, fingerprint } = req.body;

    // 2) Fire Arkada and the engine IN PARALLEL.
    //    If Arkada returns a confident approval, we abort the engine call.
    const engineAbort = new AbortController();
    const arkadaAbort = new AbortController();

    const arkadaPromise = (async () => {
        try {
            const r = await Promise.race([
                checkArkadaRank(walletAddress, { signal: arkadaAbort.signal }),
                new Promise((_, reject) =>
                    setTimeout(
                        () => reject(new Error('arkada_timeout')),
                        ARKADA_TIMEOUT_MS
                    )
                ),
            ]);
            return { ok: true, value: r };
        } catch (e) {
            return { ok: false, error: e.message || 'arkada_error' };
        }
    })();

    const enginePromise = (async () => {
        try {
            const r = await engineClient.post('', fingerprint, {
                signal: engineAbort.signal,
                headers: { 'x-request-id': reqId },
            });
            return { ok: true, value: r.data };
        } catch (e) {
            return { ok: false, error: e.message || 'engine_error' };
        }
    })();

    // 3) Wait for Arkada first (cheap path). If confident, cancel engine.
    const arkada = await arkadaPromise;
    if (
        arkada.ok &&
        arkada.value &&
        arkada.value.isVerified === true &&
        typeof arkada.value.rank === 'number' &&
        arkada.value.rank > ARKADA_RANK_THRESHOLD
    ) {
        engineAbort.abort();
        log('info', 'verify.approved', {
            reqId,
            route: 'arkada_trusted',
            rank: arkada.value.rank,
            durMs: Date.now() - startedAt,
        });
        return res.json({
            status: 'approved',
            route: 'arkada_trusted',
            ref: reqId,
        });
    }

    // 4) Otherwise, the engine result is authoritative.
    const engine = await enginePromise;
    if (!engine.ok) {
        log('error', 'verify.engine_unavailable', {
            reqId,
            err: engine.error,
            durMs: Date.now() - startedAt,
        });
        // Fail CLOSED: an unavailable engine must not approve traffic.
        return res.status(503).json({
            status: 'rejected',
            reason: 'verification_unavailable',
            ref: reqId,
        });
    }

    const data = engine.value;
    // 5) Strict, default-deny check on the engine response shape.
    if (!isPlainObject(data) || data.is_human !== true) {
        log('info', 'verify.rejected', {
            reqId,
            // flags / risk_score are logged server-side only, NEVER returned to client.
            flags: Array.isArray(data && data.flags) ? data.flags : undefined,
            risk_score: data && data.risk_score,
            arkadaRank: arkada.ok ? arkada.value.rank : null,
            durMs: Date.now() - startedAt,
        });
        return res.status(403).json({
            status: 'rejected',
            reason: 'sybil_detected',
            ref: reqId, // caller can quote this ref for support; no internals leaked
        });
    }

    log('info', 'verify.approved', {
        reqId,
        route: 'heuristics_cleared',
        risk_score: data.risk_score,
        durMs: Date.now() - startedAt,
    });
    return res.json({
        status: 'approved',
        route: 'heuristics_cleared',
        ref: reqId,
    });
});

// Catch-all error handler (last line of defense — never leak stack traces)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
    log('error', 'unhandled_error', {
        reqId: req.id,
        err: err && err.message,
    });
    res.status(500).json({ status: 'rejected', reason: 'internal_error', ref: req.id });
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
const server = app.listen(PORT, () => {
    log('info', 'startup', {
        port: PORT,
        engine: PYTHON_ENGINE_URL,
        prod: IS_PROD,
    });
});

// Graceful shutdown so in-flight verifies complete.
const shutdown = (sig) => {
    log('info', 'shutdown', { sig });
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = app;
