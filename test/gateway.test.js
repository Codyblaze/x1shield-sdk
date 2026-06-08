'use strict';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const axios = require('axios');

// Stub engine: records the body the gateway sent, replies per-test.
let lastEngineBody = null;
let engineResponder = (_req, res) => res.json({ is_human: true, risk_score: 0 });

const stub = express();
stub.use(express.json());
stub.post('/api/v1/analyze', (req, res) => {
    lastEngineBody = req.body;
    return engineResponder(req, res);
});

let stubServer;
let gatewayServer;
let gateway;

const VALID_WALLET = '0x1234567890abcdef1234567890abcdef12345678';
const FINGERPRINT = {
    interactionSequence: ['connect', 'approve', 'swap'],
    accountAgeDays: 220,
};

const listen = (server) =>
    new Promise((resolve) => {
        const s = server.listen(0, '127.0.0.1', () => resolve(s));
    });

before(async () => {
    stubServer = await listen(http.createServer(stub));
    const stubPort = stubServer.address().port;

    // Gateway reads config at import time, so env must be set before require().
    process.env.NODE_ENV = 'test';
    process.env.ENGINE_URL = `http://127.0.0.1:${stubPort}/api/v1/analyze`;
    process.env.API_KEYS = '';

    const app = require('../index');
    gatewayServer = await listen(app);
    const gatewayPort = gatewayServer.address().port;

    gateway = axios.create({
        baseURL: `http://127.0.0.1:${gatewayPort}`,
        validateStatus: () => true,
    });
});

after(() => {
    if (gatewayServer) gatewayServer.close();
    if (stubServer) stubServer.close();
});

beforeEach(() => {
    lastEngineBody = null;
    engineResponder = (_req, res) => res.json({ is_human: true, risk_score: 0 });
});

test('gateway sends the engine { walletAddress, fingerprint } (regression guard)', async () => {
    await gateway.post('/api/verify', {
        walletAddress: VALID_WALLET,
        fingerprint: FINGERPRINT,
    });

    assert.ok(lastEngineBody, 'engine should have been called');
    assert.deepEqual(Object.keys(lastEngineBody).sort(), ['fingerprint', 'walletAddress']);
    assert.equal(lastEngineBody.walletAddress, VALID_WALLET);
    assert.deepEqual(
        lastEngineBody.fingerprint.interactionSequence,
        FINGERPRINT.interactionSequence
    );
    assert.equal(lastEngineBody.fingerprint.accountAgeDays, FINGERPRINT.accountAgeDays);
    // Gateway injects the server-observed source IP on every request.
    assert.equal(typeof lastEngineBody.fingerprint.network.ip_address, 'string');
});

test('healthy engine approval -> 200 approved / heuristics_cleared', async () => {
    engineResponder = (_req, res) => res.json({ is_human: true, risk_score: 10 });

    const res = await gateway.post('/api/verify', {
        walletAddress: VALID_WALLET,
        fingerprint: FINGERPRINT,
    });

    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'approved');
    assert.equal(res.data.route, 'heuristics_cleared');
});

test('engine rejects human -> 403 sybil_detected', async () => {
    engineResponder = (_req, res) => res.json({ is_human: false, risk_score: 90 });

    const res = await gateway.post('/api/verify', {
        walletAddress: VALID_WALLET,
        fingerprint: FINGERPRINT,
    });

    assert.equal(res.status, 403);
    assert.equal(res.data.status, 'rejected');
    assert.equal(res.data.reason, 'sybil_detected');
});

test('engine error -> 503 fail-closed', async () => {
    engineResponder = (_req, res) =>
        res.status(500).json({ error: 'boom' });

    const res = await gateway.post('/api/verify', {
        walletAddress: VALID_WALLET,
        fingerprint: FINGERPRINT,
    });

    assert.equal(res.status, 503);
    assert.equal(res.data.status, 'rejected');
    assert.equal(res.data.reason, 'verification_unavailable');
});

test('nested browser_data + network pass validation; spoofed IP is overridden', async () => {
    const nestedFp = {
        interaction_sequence: ['connect', 'swap'],
        browser_data: {
            user_agent: 'Mozilla/5.0',
            fonts: ['Arial', 'Calibri'],
        },
        network: {
            ip_address: '52.1.2.3', // attacker-claimed; must be ignored
            recent_ips: ['52.1.2.3', '52.1.2.4'],
        },
    };

    const res = await gateway.post('/api/verify', {
        walletAddress: VALID_WALLET,
        fingerprint: nestedFp,
    });

    assert.equal(res.status, 200);
    assert.deepEqual(lastEngineBody.fingerprint.browser_data, nestedFp.browser_data);
    assert.deepEqual(lastEngineBody.fingerprint.network.recent_ips, nestedFp.network.recent_ips);
    // The caller's claimed ip_address is replaced by the server-observed one.
    assert.notEqual(lastEngineBody.fingerprint.network.ip_address, '52.1.2.3');
    assert.equal(typeof lastEngineBody.fingerprint.network.ip_address, 'string');
});

test('disallowed nested object is rejected with 400', async () => {
    const res = await gateway.post('/api/verify', {
        walletAddress: VALID_WALLET,
        fingerprint: { metadata: { evil: true } },
    });

    assert.equal(res.status, 400);
    assert.equal(res.data.reason, 'invalid_input');
});

test('prototype-pollution key inside allowed sub-object is rejected', async () => {
    // Sent as a raw string so "__proto__" survives JSON.parse as a real own key
    // (an object literal would treat it as the prototype and drop it).
    const raw = JSON.stringify({
        walletAddress: VALID_WALLET,
        fingerprint: { network: {} },
    }).replace('"network":{}', '"network":{"__proto__":{"polluted":true}}');

    const res = await gateway.post('/api/verify', raw, {
        headers: { 'Content-Type': 'application/json' },
    });

    assert.equal(res.status, 400);
    assert.equal(res.data.reason, 'invalid_input');
});
