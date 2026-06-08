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
    assert.deepEqual(lastEngineBody.fingerprint, FINGERPRINT);
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
