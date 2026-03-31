# MPP Security Scanner

The first vulnerability scanner for [MPP (Machine Payment Protocol)](https://tempo.xyz) services on the Tempo L1 blockchain.

The scanner itself **is** an MPP service: an agent pays $0.05–$1.00 USDC to audit any other MPP endpoint — before trusting it with real money.

```
$ mpp-scan http://target-service.com/api --tier full

                  Scan: http://target-service.com/api
┏━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID        ┃ Severity ┃ Title                                     ┃
┡━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ PRICE-001 │ CRITICAL │ Underpayment by 1 micro-USDC accepted     │
│ SESS-001  │ CRITICAL │ Session token replay accepted             │
│ RACE-001  │ CRITICAL │ Same payment accepted multiple times      │
│ VRFY-001  │ CRITICAL │ Foreign transaction hash accepted         │
│ ...       │          │                                           │
└───────────┴──────────┴───────────────────────────────────────────┘
17 findings | Duration: 1217ms
```

## Why This Exists

Before an AI agent pays an MPP service, it should know if that service is secure. No tool existed to check. Sardis Guard only scores completed transactions (reactive). We do **proactive testing** before any money moves.

## What It Checks

| Category | IDs | What it tests |
|----------|-----|---------------|
| **Price Manipulation** | PRICE-001..006 | Underpayment, decimal confusion, negative/zero amounts, overflow |
| **Session Replay** | SESS-001..004 | Token reuse, expired sessions, session swapping, missing expiry |
| **Race Conditions** | RACE-001..002 | Parallel replay (10 concurrent requests), TOCTOU |
| **Overclaiming** | OVER-001..002 | Inconsistent pricing, unreasonable prices |
| **Payment Verification** | VRFY-001..003 | Foreign txhash, underpaid tx, unconfirmed tx |
| **Malicious 402** | INJ-001..002 | Invalid destination address, bad EIP-55 checksum |
| **Denial of Service** | DOS-001..004 | Low delivery rate, timeout without refund, recursive billing |

Every finding includes a **runnable Python PoC** and remediation guidance.

## Quick Start

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- Redis (optional, falls back to in-memory)
- [Foundry](https://getfoundry.sh/) (for contract development)

### Install & Run Locally

```bash
git clone https://github.com/YOUR_USER/mpp-scanner.git
cd mpp-scanner

# Install dependencies
uv sync

# Run tests
uv run pytest tests/ -v

# Start the scanner API (dev mode, no chain verification)
MPP_SKIP_CHAIN_VERIFY=1 uv run uvicorn mpp_scanner.service.app:app --port 8000

# Scan a target via CLI
uv run python -m cli.main http://target:port/endpoint --tier quick
```

### Docker

```bash
cp .env.example .env
# Edit .env with your wallet and RPC details

docker compose up --build
# API on :8000, 3 workers, Redis, PostgreSQL
```

## Architecture

```
mpp-scanner/
├── mpp_scanner/           # Core Python package
│   ├── models.py          # Finding, Severity, ScanResult, PaymentInfo
│   ├── discovery.py       # Fingerprint MPP endpoints (parse 402 headers)
│   ├── engine.py          # Async parallel checker orchestrator
│   ├── poc.py             # PoC code generator for each finding
│   ├── reporter.py        # JSON, Markdown, SARIF output
│   ├── checks/            # 7 independent checker modules
│   │   ├── price.py       # PriceManipulationChecker
│   │   ├── session.py     # SessionReplayChecker
│   │   ├── race.py        # RaceConditionChecker
│   │   ├── overclaim.py   # OverclaimingChecker
│   │   ├── verify.py      # PaymentVerificationChecker
│   │   ├── inject.py      # Malicious402Checker
│   │   └── dos.py         # DoSChecker
│   └── service/           # FastAPI service layer
│       ├── app.py         # App factory, Redis lifespan
│       ├── middleware.py   # MPP 402 payment flow
│       ├── verifier.py    # On-chain payment verification
│       ├── chain.py       # web3.py wrapper for Tempo RPC
│       ├── cache.py       # Redis scan cache with TTL
│       ├── scheduler.py   # RQ async job queue
│       └── routers/       # scan, certificate, health endpoints
├── contracts/             # Solidity (Foundry)
│   └── src/SecurityCertificate.sol
├── cli/main.py            # Typer CLI
└── tests/                 # 31 Python tests + fixtures
```

## API

### MPP Payment Flow

All `/scan` endpoints are gated by the MPP protocol:

```
1. POST /scan               → 402 with payment headers
2. Pay USDC to X-Payment-Destination on Tempo chain
3. POST /scan               → 200 with scan results
   Headers: X-Payment-Tx, X-Payment-Session
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/scan` | MPP | Create a new scan |
| `GET` | `/scan/{id}` | MPP | Poll scan job status |
| `GET` | `/certificate/{target}` | Public | On-chain security certificate |
| `GET` | `/health` | Public | Health check |
| `GET` | `/.well-known/mpp-scanner` | Public | Service discovery & pricing |

### Pricing

| Tier | Price | Checks | Async |
|------|-------|--------|-------|
| `quick` | $0.05 | 3 critical categories | No |
| `full` | $0.25 | All 7 categories | Yes (queue) |
| `certified` | $1.00 | All + on-chain certificate | Yes (queue) |

### Output Formats

```bash
# Rich table (default)
uv run python -m cli.main http://target --tier full

# JSON
uv run python -m cli.main http://target --output json

# Markdown report
uv run python -m cli.main http://target --output markdown

# SARIF (for CI/CD integration)
uv run python -m cli.main http://target --output sarif
```

## Smart Contract

`MPPSecurityCertificate` is deployed on **Tempo Moderato testnet**:

| | |
|---|---|
| Contract | `0x8cF01fb57002CA878084cBFad43Ba105186BE722` |
| Chain | Tempo Moderato (ID: 42431) |
| RPC | `https://rpc.moderato.tempo.xyz` |
| Explorer | `https://explore.moderato.tempo.xyz` |

The contract stores on-chain security certificates:
- **`issue(target, scanId, hasCritical)`** — mint certificate (scanner only)
- **`isValid(target)`** — check if certificate exists, is not expired (24h), and has no critical findings
- **`getCertificate(target)`** — full certificate data

```bash
# Run Foundry tests
cd contracts && forge test -v
```

## Testing

```bash
# All tests (31 Python + 12 Solidity)
uv run pytest tests/ -v
cd contracts && forge test -v

# Checker tests with coverage
uv run pytest tests/test_checkers/ --cov=mpp_scanner --cov-report=term-missing

# Self-scan (scanner audits itself)
MPP_SKIP_CHAIN_VERIFY=1 uv run uvicorn mpp_scanner.service.app:app --port 8000 &
uv run python -m cli.main http://127.0.0.1:8000/scan --tier full
# → 0 findings
```

The test suite includes two mock MPP servers:
- **`mock_mpp_server.py`** — correctly implemented, should produce 0 findings
- **`vuln_mpp_server.py`** — intentionally vulnerable, should trigger all checker categories

## Environment Variables

See [`.env.example`](.env.example) for all options:

| Variable | Description |
|----------|-------------|
| `TEMPO_RPC_URL` | Tempo chain RPC endpoint |
| `SCANNER_WALLET_ADDRESS` | Scanner's wallet address |
| `SCANNER_WALLET_PRIVATE_KEY` | Private key (never commit!) |
| `CERTIFICATE_CONTRACT_ADDRESS` | Deployed SecurityCertificate address |
| `REDIS_URL` | Redis connection (optional) |
| `DATABASE_URL` | PostgreSQL connection |
| `MPP_SKIP_CHAIN_VERIFY` | Set to `1` for dev/test mode |

## Tech Stack

- **Backend:** FastAPI + uvicorn, Python 3.12
- **Package manager:** uv
- **Queue:** Redis + RQ (async scan jobs)
- **DB:** PostgreSQL (scan history)
- **Chain:** web3.py → Tempo RPC
- **Contracts:** Solidity 0.8.20 + Foundry
- **Deploy:** Docker Compose

## License

MIT
