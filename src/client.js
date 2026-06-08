'use strict';

const axios = require('axios');

const ARKADA_BYPASS_THRESHOLD = 70;
const DEFAULT_GATEWAY_URL = 'http://localhost:3000';
const DEFAULT_TIMEOUT_MS = 4000;

class X1GatewayError extends Error {
    constructor(message, meta = {}) {
        super(message);
        this.name = 'X1GatewayError';
        this.cause = meta.cause;
        this.statusCode = meta.statusCode;
        this.gatewayRef = meta.gatewayRef;
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, X1GatewayError);
        }
    }
}

class X1ShieldClient {
    constructor({ apiKey, gatewayUrl = DEFAULT_GATEWAY_URL, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
        if (!apiKey || typeof apiKey !== 'string') {
            throw new TypeError('X1ShieldClient requires a non-empty "apiKey" string.');
        }

        this.apiKey = apiKey;
        this.gatewayUrl = gatewayUrl.replace(/\/+$/, '');

        this._http = axios.create({
            baseURL: this.gatewayUrl,
            timeout: timeoutMs,
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.apiKey,
            },
        });
    }

    async _checkArkadaGlobalRank(walletAddress) {
        await new Promise((resolve) => setTimeout(resolve, 25));
        return Math.floor(Math.random() * 100) + 1;
    }

    _toEngineFingerprint(fp = {}) {
        const engineFp = {
            transactions: fp.transactions ?? [],
            funding_sources: fp.fundingSources ?? [],
            interaction_sequence: fp.interactionSequence ?? [],
            account_age_days: fp.accountAgeDays ?? 0,
            unique_contracts: fp.uniqueContracts ?? 0,
        };

        if (fp.browserData) {
            const b = fp.browserData;
            engineFp.browser_data = {
                user_agent: b.userAgent ?? null,
                platform: b.platform ?? null,
                fonts: b.fonts ?? [],
                webgl_renderer: b.webglRenderer ?? null,
            };
        }

        if (fp.network) {
            const n = fp.network;
            engineFp.network = {
                ip_address: n.ipAddress ?? null,
                recent_ips: n.recentIps ?? [],
            };
        }

        return engineFp;
    }

    async verifyTransaction(walletAddress, browserFingerprintData) {
        const arkadaRank = await this._checkArkadaGlobalRank(walletAddress);
        if (arkadaRank > ARKADA_BYPASS_THRESHOLD) {
            return {
                isHuman: true,
                reason: 'Passed via Arkada',
                arkadaRank,
            };
        }

        const fingerprint = this._toEngineFingerprint(browserFingerprintData);

        let response;
        try {
            response = await this._http.post('/api/verify', {
                walletAddress,
                fingerprint,
            });
        } catch (err) {
            if (err.response) {
                const { status, data } = err.response;
                const gatewayRef = data && data.ref;

                if (status === 403) {
                    return {
                        isHuman: false,
                        reason: 'Sybil signals detected',
                        ref: gatewayRef,
                    };
                }

                throw new X1GatewayError(
                    'X1 Shield gateway is currently unreachable.',
                    { statusCode: status, gatewayRef, cause: err }
                );
            }

            throw new X1GatewayError(
                'X1 Shield gateway is currently unreachable.',
                { cause: err }
            );
        }

        const data = response.data || {};
        if (data.status === 'approved') {
            return {
                isHuman: true,
                reason: 'Cleared by heuristics gateway',
                route: data.route,
                ref: data.ref,
            };
        }

        return {
            isHuman: false,
            reason: 'Not approved by heuristics gateway',
            route: data.route,
            ref: data.ref,
        };
    }
}

module.exports = { X1ShieldClient, X1GatewayError };
