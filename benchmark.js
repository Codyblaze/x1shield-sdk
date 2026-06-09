'use strict';

const autocannon = require('autocannon');
const crypto = require('crypto');

const TARGET_URL = process.env.BENCH_URL || 'http://127.0.0.1:3000/api/verify';
const TARGET_RATE = Number(process.env.BENCH_RATE) || 500;
const DURATION_SECONDS = Number(process.env.BENCH_DURATION) || 10;
const CONNECTIONS = Number(process.env.BENCH_CONNECTIONS) || 50;
const API_KEY = process.env.BENCH_API_KEY || '';
const LATENCY_BUDGET_MS = Number(process.env.BENCH_LATENCY_BUDGET_MS) || 200;
// Default measures the cold verification path. Set BENCH_CACHED=1 to reuse a
// single wallet and benchmark the Redis-accelerated repeat path instead.
const CACHED = process.env.BENCH_CACHED === '1';

const STATIC_WALLET = '0x1234567890abcdef1234567890abcdef12345678';
const randomWallet = () => '0x' + crypto.randomBytes(20).toString('hex');

const buildBody = (walletAddress) =>
    JSON.stringify({
        walletAddress,
        fingerprint: {
            interactionSequence: ['connect', 'approve', 'swap'],
            accountAgeDays: 220,
            uniqueContracts: 14,
            browserData: {
                userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                platform: 'Win32',
                fonts: ['Arial', 'Calibri', 'Segoe UI'],
                webglRenderer: 'ANGLE (NVIDIA GeForce RTX 3070 Direct3D11)',
            },
        },
    });

const headers = { 'content-type': 'application/json' };
if (API_KEY) headers['x-api-key'] = API_KEY;

// A unique wallet per request changes the verdict cache key, forcing every
// call down the full Arkada + engine path so the result reflects real
// verification latency rather than cache hits.
const setupRequest = (req) => {
    req.body = buildBody(CACHED ? STATIC_WALLET : randomWallet());
    return req;
};

const run = () =>
    autocannon({
        url: TARGET_URL,
        method: 'POST',
        connections: CONNECTIONS,
        overallRate: TARGET_RATE,
        duration: DURATION_SECONDS,
        headers,
        body: buildBody(STATIC_WALLET),
        requests: [{ setupRequest }],
    });

async function main() {
    const instance = run();
    autocannon.track(instance, { renderProgressBar: true, renderResultsTable: false });

    const result = await instance;
    // autocannon's hdr histogram exposes p97_5, not p95; use it as a stricter
    // stand-in for the p95 budget so the milestone check reads a real value.
    const { p50, p97_5: p975, p99 } = result.latency;
    const throughput = result.requests.average;
    const nonSuccess = result.non2xx + (result['4xx'] || 0);

    const passed =
        nonSuccess === 0 && p975 < LATENCY_BUDGET_MS && p99 < LATENCY_BUDGET_MS;

    process.stdout.write('\n');
    process.stdout.write('X1 Shield Gateway Latency Benchmark\n');
    process.stdout.write(`  mode              ${CACHED ? 'cached (repeat wallet)' : 'cold (unique wallet/req)'}\n`);
    process.stdout.write(`  target            ${TARGET_URL}\n`);
    process.stdout.write(`  requested rate    ${TARGET_RATE} req/s for ${DURATION_SECONDS}s\n`);
    process.stdout.write(`  achieved rate     ${throughput.toFixed(1)} req/s\n`);
    process.stdout.write(`  latency p50       ${p50} ms\n`);
    process.stdout.write(`  latency p97.5     ${p975} ms\n`);
    process.stdout.write(`  latency p99       ${p99} ms\n`);
    process.stdout.write(`  non-2xx responses ${nonSuccess}\n`);
    process.stdout.write(
        `  milestone (<${LATENCY_BUDGET_MS}ms p97.5 & p99)  ${passed ? 'PASS' : 'FAIL'}\n`
    );

    process.exitCode = passed ? 0 : 1;
}

main().catch((err) => {
    process.stderr.write(`benchmark failed: ${err && err.message}\n`);
    process.exitCode = 1;
});
