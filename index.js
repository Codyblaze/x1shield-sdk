'use strict';

const express = require('express');
const axios = require('axios');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const PYTHON_ENGINE_URL =
    process.env.ENGINE_URL || 'http://127.0.0.1:8000/api/v1/analyze';
const ENGINE_TIMEOUT_MS = Number(process.env.ENGINE_TIMEOUT_MS) || 1500;
const ARKADA_TIMEOUT_MS = Number(process.env.ARKADA_TIMEOUT_MS) || 800;
const ARKADA_RANK_THRESHOLD = Number(process.env.ARKADA_RANK_THRESHOLD) || 50;
const MAX_BODY_BYTES = process.env.MAX_BODY_BYTES || '32kb';
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 60_000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 60;
const API_KEYS = (process.env.API_KEYS || '')
    .split(',')
    .map((k) => k.trim())
    .filter(Boolean);
const IS_PROD = process.env.NODE_ENV === 'production';

if (IS_PROD && !process.env.ENGINE_URL) {
    // eslint-disable-next-line no-console
    console.error('FATAL: ENGINE_URL must be set explicitly in production.');
    process.exit(1);
}
if (IS_PROD && API_KEYS.length === 0) {
    // eslint-disable-next-line no-console
    console.error('FATAL: API_KEYS must be set in production.');
    process.exit(1);
}

const log = (level, msg, fields = {}) => {
    // eslint-disable-next-line no-console
    console.log(
        JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields })
    );
};

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 50 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 50 });
const engineClient = axios.create({
    baseURL: PYTHON_ENGINE_URL,
    timeout: ENGINE_TIMEOUT_MS,
    httpAgent,
    httpsAgent,
    // Any non-2xx must reach the catch path so a degraded engine fails closed.
    validateStatus: (s) => s >= 200 && s < 300,
});

// In-memory limiter; swap for Redis once the gateway runs multi-instance.
const rateBuckets = new Map();
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

setInterval(() => {
    const now = Date.now();
    for (const [ip, b] of rateBuckets) {
        if (b.resetAt < now) rateBuckets.delete(ip);
    }
}, RATE_LIMIT_WINDOW_MS).unref();

const requireApiKey = (req, res, next) => {
    // Auth is bypassable only when unconfigured outside production.
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

const attachRequestId = (req, res, next) => {
    const incoming = req.get('x-request-id');
    req.id = incoming && /^[a-zA-Z0-9_-]{1,64}$/.test(incoming)
        ? incoming
        : crypto.randomUUID();
    res.setHeader('x-request-id', req.id);
    next();
};

const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const MAX_FINGERPRINT_KEYS = 64;
const MAX_FINGERPRINT_STRING_LEN = 2048;

const isPlainObject = (v) =>
    v !== null && typeof v === 'object' && !Array.isArray(v);

// Known sub-objects allowed to nest exactly one level (snake_case + camelCase).
const ALLOWED_NESTED_KEYS = new Set([
    'browser_data',
    'browserData',
    'network',
]);

const isForbiddenKey = (k) =>
    k === '__proto__' || k === 'constructor' || k === 'prototype';

// Validates a single flat level: primitives or arrays of primitives only.
const validateFlatLevel = (obj) => {
    const keys = Object.keys(obj);
    if (keys.length > MAX_FINGERPRINT_KEYS) return 'fingerprint_too_many_keys';
    for (const k of keys) {
        if (isForbiddenKey(k)) return 'fingerprint_forbidden_key';
        const v = obj[k];
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

const validateFingerprint = (fp) => {
    if (!isPlainObject(fp)) return 'fingerprint_must_be_object';
    const keys = Object.keys(fp);
    if (keys.length === 0) return 'fingerprint_empty';
    if (keys.length > MAX_FINGERPRINT_KEYS) return 'fingerprint_too_many_keys';
    for (const k of keys) {
        if (isForbiddenKey(k)) return 'fingerprint_forbidden_key';
        const v = fp[k];
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
            // Only whitelisted sub-objects may nest, and only one level deep.
            if (!ALLOWED_NESTED_KEYS.has(k)) return 'fingerprint_nested_object';
            const nestedErr = validateFlatLevel(v);
            if (nestedErr) return nestedErr;
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

const arkadaCache = new Map();
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
        // Evict oldest; Map iteration follows insertion order.
        const firstKey = arkadaCache.keys().next().value;
        if (firstKey !== undefined) arkadaCache.delete(firstKey);
    }
    arkadaCache.set(addr, { value, expiresAt: Date.now() + ARKADA_CACHE_TTL_MS });
};

const checkArkadaRank = async (walletAddress, { signal } = {}) => {
    const cached = cacheGet(walletAddress);
    if (cached) return cached;

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
        // Mock must never grant trust off attacker-controlled input.
        const value = { isVerified: false, rank: 12, source: 'mock' };
        cacheSet(walletAddress, value);
        return value;
    }

    throw new Error('arkada_client_not_configured');
};

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS) || 0);
app.use(express.json({ limit: MAX_BODY_BYTES }));
app.use(attachRequestId);

app.use((err, req, res, next) => {
    if (err && err.type === 'entity.too.large') {
        return res.status(413).json({ status: 'rejected', reason: 'payload_too_large' });
    }
    if (err && err.type === 'entity.parse.failed') {
        return res.status(400).json({ status: 'rejected', reason: 'malformed_json' });
    }
    return next(err);
});

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/ready', async (_req, res) => {
    // Deliberately skips the engine to avoid readiness-probe amplification.
    res.json({ ok: true, engine: PYTHON_ENGINE_URL });
});

app.post('/api/verify', rateLimit, requireApiKey, async (req, res) => {
    const reqId = req.id;
    const startedAt = Date.now();

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

    // The source IP must come from the connection, not the caller. A client
    // could otherwise claim a residential IP to dodge datacenter detection.
    fingerprint.network = {
        ...(isPlainObject(fingerprint.network) ? fingerprint.network : {}),
        ip_address: req.ip,
    };

    // Race Arkada against the engine; a confident Arkada pass cancels the engine.
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
            const r = await engineClient.post('', { walletAddress, fingerprint }, {
                signal: engineAbort.signal,
                headers: { 'x-request-id': reqId },
            });
            return { ok: true, value: r.data };
        } catch (e) {
            return { ok: false, error: e.message || 'engine_error' };
        }
    })();

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

    const engine = await enginePromise;
    if (!engine.ok) {
        log('error', 'verify.engine_unavailable', {
            reqId,
            err: engine.error,
            durMs: Date.now() - startedAt,
        });
        // Fail closed: an unavailable engine must never approve traffic.
        return res.status(503).json({
            status: 'rejected',
            reason: 'verification_unavailable',
            ref: reqId,
        });
    }

    const data = engine.value;
    if (!isPlainObject(data) || data.is_human !== true) {
        log('info', 'verify.rejected', {
            reqId,
            // Scores/flags stay server-side; detection internals are never returned.
            flags: Array.isArray(data && data.flags) ? data.flags : undefined,
            risk_score: data && data.risk_score,
            arkadaRank: arkada.ok ? arkada.value.rank : null,
            durMs: Date.now() - startedAt,
        });
        return res.status(403).json({
            status: 'rejected',
            reason: 'sybil_detected',
            ref: reqId,
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

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
    log('error', 'unhandled_error', {
        reqId: req.id,
        err: err && err.message,
    });
    res.status(500).json({ status: 'rejected', reason: 'internal_error', ref: req.id });
});

// Bind a port only when run directly so test imports stay side-effect free.
if (require.main === module) {
    const server = app.listen(PORT, () => {
        log('info', 'startup', {
            port: PORT,
            engine: PYTHON_ENGINE_URL,
            prod: IS_PROD,
        });
    });

    const shutdown = (sig) => {
        log('info', 'shutdown', { sig });
        server.close(() => process.exit(0));
        setTimeout(() => process.exit(1), 10_000).unref();
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = app;
