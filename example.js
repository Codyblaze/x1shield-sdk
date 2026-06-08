'use strict';

const { X1ShieldClient, X1GatewayError } = require('./src/client');

const shield = new X1ShieldClient({
    apiKey: 'x1_sk_test_mock_dapp_key',
});

const walletAddress = '0x1234567890abcdef1234567890abcdef12345678';

const browserFingerprintData = {
    transactions: [
        { tx_hash: '0xaaa', timestamp: '2026-01-01T10:00:00Z', value: 1.5, method: 'swap' },
        { tx_hash: '0xbbb', timestamp: '2026-01-01T10:04:00Z', value: 0.2, method: 'approve' },
    ],
    fundingSources: [
        { address: '0xexchange01', amount: 5.0, timestamp: '2025-12-30T08:00:00Z', source_type: 'cex' },
    ],
    interactionSequence: ['connect', 'approve', 'swap', 'disconnect'],
    accountAgeDays: 220,
    uniqueContracts: 14,
    browserData: {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        platform: 'Win32',
        fonts: ['Arial', 'Calibri', 'Segoe UI', 'Times New Roman', 'Verdana'],
        webglRenderer: 'ANGLE (NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0)',
    },
};

async function main() {
    try {
        const result = await shield.verifyTransaction(walletAddress, browserFingerprintData);

        if (result.isHuman) {
            console.log(`[dApp] Verification PASSED (${result.reason}). Proceeding with transaction.`);
        } else {
            console.log(`[dApp] Verification FAILED (${result.reason}). Blocking transaction.`);
            if (result.ref) console.log(`[dApp] Support reference: ${result.ref}`);
        }
    } catch (err) {
        if (err instanceof X1GatewayError) {
            console.error(`[dApp] X1 Shield unavailable: ${err.message}`);
            if (err.statusCode) console.error(`[dApp] Gateway status: ${err.statusCode}`);

            const FAIL_CLOSED = true;
            if (FAIL_CLOSED) {
                console.error('[dApp] Fail-closed policy active: blocking transaction.');
                return;
            }

            return;
        }

        console.error('[dApp] Unexpected error during verification:', err);
        process.exitCode = 1;
    }
}

main();
