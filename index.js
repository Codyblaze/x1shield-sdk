const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
// Pointing to your local Python heuristics engine
const PYTHON_ENGINE_URL = process.env.ENGINE_URL || 'http://127.0.0.1:8000/api/v1/analyze';

// mock arkada global rank check
const checkArkadaRank = async (walletAddress) => {
    // prod: ping the Arkada contract/API on X1 EcoChain
    // mock: assume unverified to force the heavy heuristics check
    return { isVerified: false, rank: 0 };
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