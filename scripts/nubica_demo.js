'use strict';

const { ethers } = require('ethers');
const { X1ShieldClient, X1GatewayError } = require('../src/client');

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';
const API_KEY = process.env.X1_API_KEY || 'x1_sk_test_mock_dapp_key';
const NUBICA_RPC_URL = process.env.NUBICA_RPC_URL || '';
const NUBICA_CHAIN_ID = process.env.NUBICA_CHAIN_ID
    ? Number(process.env.NUBICA_CHAIN_ID)
    : undefined;
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY || '';

const walletAddress = '0x1234567890abcdef1234567890abcdef12345678';

const mockFingerprint = {
    transactions: [
        { tx_hash: '0xaaa', timestamp: '2026-01-01T10:00:00Z', value: 1.5, method: 'swap' },
    ],
    fundingSources: [
        { address: '0xexchange01', amount: 5.0, timestamp: '2025-12-30T08:00:00Z', source_type: 'cex' },
    ],
    interactionSequence: ['connect', 'approve', 'swap', 'disconnect'],
    accountAgeDays: 220,
    uniqueContracts: 14,
    browserData: {
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        platform: 'Win32',
        fonts: ['Arial', 'Calibri', 'Segoe UI'],
        webglRenderer: 'ANGLE (NVIDIA GeForce RTX 3070 Direct3D11)',
    },
};

const broadcastOnNubica = async (signer) => {
    const tx = await signer.sendTransaction({ to: signer.address, value: 0n });
    console.log(`[nubica] broadcast tx ${tx.hash}`);
    const receipt = await tx.wait();
    console.log(
        `[nubica] confirmed in block ${receipt.blockNumber} (status ${receipt.status})`
    );
    return receipt;
};

// Offline path keeps the milestone demo runnable without a live RPC or funded
// key: the gate decision is still proven by producing a real signed payload.
const signOffline = async () => {
    const ephemeral = ethers.Wallet.createRandom();
    const signed = await ephemeral.signTransaction({
        to: ephemeral.address,
        value: 0n,
        nonce: 0,
        gasLimit: 21_000n,
        maxFeePerGas: ethers.parseUnits('1', 'gwei'),
        maxPriorityFeePerGas: ethers.parseUnits('1', 'gwei'),
        chainId: NUBICA_CHAIN_ID ?? 1,
    });
    console.log('[nubica] no live RPC configured; produced offline signed tx:');
    console.log(`[nubica] signer ${ephemeral.address}`);
    console.log(`[nubica] raw    ${signed}`);
    return signed;
};

async function main() {
    const shield = new X1ShieldClient({ apiKey: API_KEY, gatewayUrl: GATEWAY_URL });

    let verdict;
    try {
        verdict = await shield.verifyTransaction(walletAddress, mockFingerprint);
    } catch (err) {
        if (err instanceof X1GatewayError) {
            console.error(`[nubica] gate unavailable: ${err.message}`);
            console.error('[nubica] fail-closed: aborting transaction.');
            process.exitCode = 1;
            return;
        }
        throw err;
    }

    if (!verdict.isHuman) {
        console.log(`[nubica] BLOCKED: ${verdict.reason}`);
        if (verdict.ref) console.log(`[nubica] gateway ref ${verdict.ref}`);
        return;
    }

    console.log(`[nubica] HUMAN VERIFIED: ${verdict.reason}`);

    if (NUBICA_RPC_URL && DEPLOYER_PRIVATE_KEY) {
        const provider = new ethers.JsonRpcProvider(NUBICA_RPC_URL, NUBICA_CHAIN_ID);
        const signer = new ethers.Wallet(DEPLOYER_PRIVATE_KEY, provider);
        try {
            await broadcastOnNubica(signer);
        } finally {
            provider.destroy();
        }
        return;
    }

    await signOffline();
}

main().catch((err) => {
    console.error('[nubica] unexpected failure:', err && err.message);
    process.exitCode = 1;
});
