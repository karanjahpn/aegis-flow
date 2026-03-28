# AEGIS-FLOW

**Self-Verifying Runtime Integrity System with Distributed Trust Anchoring**

[![CI](https://github.com/karanjahpn/aegis-flow/actions/workflows/ci.yml/badge.svg)](https://github.com/karanjahpn/aegis-flow/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![Solidity](https://img.shields.io/badge/solidity-0.8.20-purple.svg)](https://soliditylang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

AEGIS-FLOW transforms software into a **continuously verified execution environment**. Instead of waiting for breach detection tools to catch an attack after the fact, AEGIS-FLOW continuously fingerprints runtime state, verifies it inside a simulated Trusted Execution Environment, and anchors proofs to an immutable distributed ledger.

```
┌────────────────────────────────────────────────────────────┐
│                    AEGIS-FLOW v1.0.0                       │
│                                                            │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Fingerprint │───▶│   Enclave    │───▶│  Blockchain  │  │
│  │   Engine    │    │  Simulator   │    │   Anchor     │  │
│  └─────────────┘    └──────────────┘    └──────────────┘  │
│         │                  │                               │
│         ▼                  ▼                               │
│  ┌─────────────┐    ┌──────────────┐                       │
│  │  Continuous │    │    Alert     │                       │
│  │   Monitor   │───▶│   Manager   │                       │
│  └─────────────┘    └──────────────┘                       │
└────────────────────────────────────────────────────────────┘
```

### What it prevents

| Attack Vector | AEGIS-FLOW Response |
|---|---|
| Code injection | State hash mismatch detected immediately |
| Replay attacks | Per-check cryptographic nonces |
| Memory tampering | Process memory included in fingerprint |
| Module hijacking | Loaded modules hashed at every check |
| Alert spoofing | All alerts are HMAC-signed by the enclave |
| Log deletion | State hashes anchored immutably on-chain |

---

## Architecture

### Component Map

```
aegis-flow/
├── core/
│   ├── fingerprint.py     # State hashing engine (SHA-256)
│   ├── monitor.py         # Continuous monitoring loop
│   └── alert.py           # Alert manager + hook system
│
├── enclave/
│   └── sim.py             # TEE simulator (HMAC signing, nonce validation)
│
├── blockchain/
│   ├── AegisRegistry.sol  # EVM smart contract (chain-agnostic)
│   ├── client.py          # Python web3 client
│   ├── deploy.js          # Hardhat deployment script
│   └── test/
│       └── AegisRegistry.test.js
│
├── tests/
│   └── test_aegis.py      # Full Python test suite
│
├── scripts/
│   ├── setup.sh           # One-command local setup
│   └── git_init.sh        # Git repo initialiser
│
├── .github/
│   └── workflows/
│       └── ci.yml         # GitHub Actions CI/CD
│
├── main.py                # CLI entry point
├── requirements.txt
├── hardhat.config.js
├── package.json
└── .env.example
```

### Data Flow

```
1. On startup:
   compute_baseline() → SHA-256(memory + modules + env + platform)
   enclave.seal_baseline(hash)

2. Every N seconds:
   nonce = generate_nonce()           # Fresh cryptographic nonce
   current = compute_fingerprint()    # Snapshot current runtime
   result  = compare_states()         # Diff against baseline
   verdict = enclave.verify()         # TEE validates + signs

3. On violation:
   alert_manager.fire()               # Signed alert dispatched
   blockchain_client.anchor_alert()   # Immutable on-chain record
   self_heal() if critical            # Automated response

4. On-chain (AegisRegistry):
   registerState(hash, severity)      # Every clean check (optional)
   anchorAlert(alertId, hash, sev)    # Every violation
```

### State Fingerprint Formula

```
State_t = SHA256(
    process.memory_rss  ||
    process.num_threads ||
    SHA256(loaded_modules) ||
    SHA256(env_variables)  ||
    platform_info          ||
    nonce_t
)
```

---

## Quick Start

### Prerequisites

| Tool | Minimum Version |
|---|---|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | 9+ |
| Git | any |

### 1 — Clone & Setup

```bash
git clone https://github.com/karanjahpn/aegis-flow.git
cd aegis-flow

chmod +x scripts/setup.sh
./scripts/setup.sh
```

This single command:
- Creates a Python virtual environment
- Installs all Python + Node dependencies
- Compiles the Solidity contract
- Runs the full test suite
- Creates your `.env` file

### 2 — Run the Monitor

```bash
source venv/bin/activate
python main.py
```

Expected output:
```
╔══════════════════════════════════════════════════════════╗
║           AEGIS-FLOW  v1.0.0                            ║
║   Self-Verifying Runtime Integrity System               ║
╚══════════════════════════════════════════════════════════╝

2024-01-15 10:23:01 [INFO] aegis.main — Computing baseline state fingerprint…
2024-01-15 10:23:01 [INFO] aegis.main — Baseline established: hash=a3f1c8d2e4b7…
2024-01-15 10:23:01 [INFO] aegis.monitor — AEGIS-FLOW Monitor started (interval=2.0s)
2024-01-15 10:23:01 [INFO] aegis.main — Monitor running. Press Ctrl+C to stop.
2024-01-15 10:23:03 [DEBUG] aegis.monitor — [CHECK #1] ✅ Integrity OK — hash=a3f1c8d2e4b7…
2024-01-15 10:23:05 [DEBUG] aegis.monitor — [CHECK #2] ✅ Integrity OK — hash=9d2e1a4f8c3b…
```

### 3 — Run a Single Check

```bash
python main.py --once
```

Returns a JSON integrity report and exits with code `0` (clean) or `1` (violation).

---

## CLI Reference

```
usage: main.py [-h] [--interval FLOAT] [--no-heal] [--log-file PATH]
               [--blockchain] [--rpc-url URL] [--contract ADDR]
               [--private-key HEX] [--duration INT] [--once] [--verbose]

Options:
  --interval FLOAT    Check interval in seconds (default: 2.0)
  --no-heal           Disable automatic self-healing on critical violations
  --log-file PATH     Append alerts as JSONL to this file
  --blockchain        Enable EVM blockchain anchoring
  --rpc-url URL       JSON-RPC endpoint (e.g. http://127.0.0.1:8545)
  --contract ADDR     Deployed AegisRegistry contract address
  --private-key HEX   Ethereum account private key for signing TXs
  --duration INT      Run for N seconds then exit (0 = forever)
  --once              Run one check and exit (0=OK, 1=violation)
  --verbose           Enable DEBUG logging
```

---

## Blockchain Setup (Optional)

The blockchain layer is **fully optional**. The monitor runs perfectly without it. Enable it to get an immutable, tamper-proof audit trail.

### Chain-Agnostic Design

`AegisRegistry.sol` is standard EVM Solidity — deploy to any compatible chain:

| Chain | Config Key |
|---|---|
| Local Hardhat | `localhost` |
| Ethereum Sepolia | `sepolia` |
| Polygon | `polygon` |
| Ethereum Mainnet | `mainnet` |
| Any EVM chain | Add to `hardhat.config.js` |

### Step 1 — Start a local node

```bash
npm run node
# Hardhat network running at http://127.0.0.1:8545
# Test accounts with 10000 ETH each printed to console
```

### Step 2 — Deploy the contract

```bash
# In a new terminal:
npm run deploy:local
```

Output:
```
AEGIS-FLOW :: Deploying AegisRegistry
Deployer : 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Balance  : 10000.0 ETH

✅ AegisRegistry deployed!
   Contract address : 0x5FbDB2315678afecb367f032d93F642f64180aa3
   TX hash          : 0xabc...

Add to .env:
   AEGIS_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
```

### Step 3 — Update `.env`

```bash
AEGIS_BLOCKCHAIN_ENABLED=true
AEGIS_RPC_URL=http://127.0.0.1:8545
AEGIS_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
AEGIS_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### Step 4 — Run with blockchain anchoring

```bash
python main.py --blockchain \
  --rpc-url http://127.0.0.1:8545 \
  --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

---

## Smart Contract Reference

**`AegisRegistry.sol`** — Stores cryptographic integrity proofs on-chain.

### Key Functions

```solidity
// Register a runtime state hash
function registerState(bytes32 stateHash, string calldata severity) external

// Query a registered hash
function verifyState(bytes32 stateHash)
    external view
    returns (bool exists, address node, uint256 timestamp, string memory severity)

// Anchor a signed alert
function anchorAlert(bytes32 alertId, bytes32 stateHash, string calldata severity) external

// Node management (owner only)
function authoriseNode(address node) external
function revokeNode(address node) external
```

### Events

```solidity
event StateRegistered(address indexed node, bytes32 indexed stateHash, uint256 timestamp, string severity)
event AlertAnchored(address indexed node, bytes32 indexed alertId, bytes32 stateHash, string severity, uint256 timestamp)
event NodeAuthorised(address indexed node, address indexed by)
event NodeRevoked(address indexed node, address indexed by)
```

---

## Alert System

### Severity Levels

| Level | Trigger | Action |
|---|---|---|
| `INFO` | Clean check (blockchain log) | Log only |
| `WARNING` | First drift detected | Alert dispatched |
| `CRITICAL` | N consecutive violations | Alert + self-heal |

### Alert Structure

Every alert is HMAC-signed by the enclave and contains:

```json
{
  "alert_id": "a3f1c8d2e4b79f12",
  "timestamp": 1705312981.45,
  "severity": "WARNING",
  "state_hash": "9d2e1a4f8c3b...",
  "drift_fields": ["memory_rss", "num_threads"],
  "drift_detail": [
    {"field": "memory_rss", "baseline": 52428800, "current": 68157440, "delta": 15728640}
  ],
  "enclave_verdict": {"valid": false, "reason": "state_hash mismatch"},
  "signed_by_enclave": "d4e5f6a7b8c9...",
  "alert_signature": "1a2b3c4d5e6f..."
}
```

### Adding Alert Hooks

```python
from core.alert import file_hook, webhook_hook
from core.monitor import MonitorConfig

config = MonitorConfig(
    alert_hooks=[
        file_hook("logs/alerts.jsonl"),
        webhook_hook("https://hooks.slack.com/your-webhook"),
    ]
)
```

---

## Running Tests

### Python Tests

```bash
source venv/bin/activate
pytest tests/ -v --cov=core --cov=enclave
```

### Solidity Tests

```bash
npx hardhat test
```

### Full CI (both)

```bash
./scripts/setup.sh   # runs pytest automatically at end
npx hardhat test
```

---

## Publishing to GitHub

Run the included script — it initialises a local git repo and guides you through pushing:

```bash
chmod +x scripts/git_init.sh
./scripts/git_init.sh
```

Then follow the printed instructions to create the repo on GitHub and push.

---

## Security Considerations

| Aspect | v1 Status | Production Path |
|---|---|---|
| TEE | Simulated (HMAC) | Replace `enclave/sim.py` with Intel SGX SDK |
| Signing key | In-memory (ephemeral) | HSM / enclave-sealed key |
| Nonce TTL | 30 seconds | Tune to your check interval |
| Memory tolerance | ±5 MB | Calibrate per workload |
| Blockchain key | `.env` | Hardware wallet / KMS |

---

## Roadmap

- [ ] **v1.1** — AI anomaly scoring layer (ML-based drift classification)
- [ ] **v1.2** — Intel SGX enclave integration (real TEE)
- [ ] **v1.3** — Cross-node distributed verification mesh
- [ ] **v1.4** — Decentralised Identity (DID) node authentication
- [ ] **v2.0** — Hardware attestation + token economy for validators

---

## License

MIT — see [LICENSE](LICENSE)

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes and add tests
4. Run: `pytest tests/ -v && npx hardhat test`
5. Open a pull request

---

*AEGIS-FLOW — Reactive Security → Continuous Verified Execution*
