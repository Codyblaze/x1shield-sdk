const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
// Pointing to your local Python heuristics engine
const PYTHON_ENGINE_URL = process.env.ENGINE_URL || 'http://127.0.0.1:8000/api/v1/analyze';

// Mock Arkada Global Rank Service
const checkArkadaRank = async (walletAddress) => {
    console.log(`[Arkada Mock] Simulating reputation check for ${walletAddress}...`);
    
    // 1. Simulate real-world network/RPC latency (50ms - 150ms)
    const latency = Math.floor(Math.random() * 100) + 50;
    await new Promise(resolve => setTimeout(resolve, latency));

    // 2. Routing Logic Test: 
    // If we pass a wallet starting with '0xTRUST', simulate a high-reputation user
    if (walletAddress && walletAddress.startsWith('0xTRUST')) {
        console.log(`[Arkada Mock] Wallet verified. Rank: 85`);
        return { isVerified: true, rank: 85 };
    }
    
    // 3. Default: Simulate low/no reputation to force the Python Heuristics check
    console.log(`[Arkada Mock] Wallet unverified. Routing to deep heuristics...`);
    return { isVerified: false, rank: 12 };
};

app.post('/api/verify', async (req, res) => {
    try {
        const { walletAddress, fingerprint } = req.body;

        // 1. fast path: check reputation layer
        const arkadaStatus = await checkArkadaRank(walletAddress);
        if (arkadaStatus.isVerified && arkadaStatus.rank > 50) {
            return res.json({ status: 'approved', route: 'arkada_trusted' });
        }

        // 2. heavy path: fallback to local python engine
        const engineResponse = await axios.post(PYTHON_ENGINE_URL, fingerprint);
        const { is_human, risk_score, flags } = engineResponse.data;

        if (!is_human) {
            return res.status(403).json({
                status: 'rejected',
                reason: 'sybil_detected',
                risk_score,
                flags
            });
        }

        res.json({
            status: 'approved',
            route: 'heuristics_cleared',
            risk_score
        });

    } catch (error) {
        console.error('engine timeout/error:', error.message);
        res.status(500).json({ error: 'verification_unavailable' });
    }
});

app.listen(PORT, () => {
    console.log(`x1 shield middleware active on port ${PORT}`);
});