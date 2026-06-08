# X1 Shield Node.js SDK (Alpha)

The middleware layer for X1 Shield. This Express service acts as the logic gate for dApps on the X1 EcoChain. 

### Execution Flow:
1. Receives wallet address and browser fingerprint payload.
2. Cross-references the wallet against the **Arkada Global Rank** reputation layer.
3. If unverified, routes the raw browser fingerprint to the localized Python heuristics engine for deep headless-execution analysis.