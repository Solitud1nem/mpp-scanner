<p align="center">
  <h1 align="center">MPP Security Scanner</h1>
  <p align="center">
    The first proactive vulnerability scanner for Machine Payment Protocol services on Tempo L1 — itself paid via MPP.
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-43%20passing-brightgreen" alt="tests">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="python">
  <img src="https://img.shields.io/badge/solidity-0.8.20-363636" alt="solidity">
  <img src="https://img.shields.io/badge/contract-deployed-success" alt="contract">
  <img src="https://img.shields.io/badge/self--scan-0%20findings-brightgreen" alt="self-scan">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="license">
</p>

---

## The Problem

AI agents pay MPP services without knowing if they're secure. A malicious service can replay sessions, accept fake payments, or charge more than declared. No tool existed to check this **before** money moves.

**Sardis Guard** scores completed transactions — reactive, after the damage.
**MPP Scanner** tests endpoints proactively — before a single cent leaves your wallet.

---

## Proof: We Scan Ourselves

```
$ mpp-scan http://localhost:8000/scan --tier full

┏━━━━┳━━━━━━━━━━┳━━━━━━━┓
┃ ID ┃ Severity ┃ Title ┃
┡━━━━╇━━━━━━━━━━╇━━━━━━━┩
└────┴──────────┴───────┘
0 findings | Duration: 1033ms
```

The scanner passes its own audit. Zero vulnerabilities.

Now the same scan against a vulnerable MPP service:

```
$ mpp-scan http://localhost:9000/service --tier full

┏━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID        ┃ Severity ┃ Title                                                 ┃
┡━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ PRICE-001 │ CRITICAL │ Underpayment by 1 micro-USDC accepted                 │
│ PRICE-004 │ CRITICAL │ Negative amount accepted                              │
│ PRICE-005 │ CRITICAL │ Zero amount accepted                                  │
│ SESS-001  │ CRITICAL │ Session token replay accepted                         │
│ RACE-001  │ CRITICAL │ Race condition: same payment accepted multiple times  │
│ VRFY-001  │ CRITICAL │ Foreign transaction hash accepted as payment          │
│ VRFY-002  │ CRITICAL │ Underpaid transaction accepted                        │
│ PRICE-002 │ HIGH     │ Decimal confusion (18 vs 6 decimals) accepted         │
│ PRICE-003 │ HIGH     │ Float representation attack accepted                  │
│ PRICE-006 │ HIGH     │ Integer overflow (2^256-1) accepted                   │
│ SESS-002  │ HIGH     │ Expired session token accepted                        │
│ SESS-003  │ HIGH     │ Session ID swap accepted                              │
│ RACE-002  │ HIGH     │ TOCTOU: additional requests accepted after payment    │
│ OVER-001  │ HIGH     │ Inconsistent pricing across requests                  │
│ VRFY-003  │ HIGH     │ Unconfirmed (pending) transaction accepted            │
│ SESS-004  │ MEDIUM   │ Missing X-Payment-Expires header in 402               │
│ INJ-002   │ MEDIUM   │ Invalid checksum address accepted                     │
└───────────┴──────────┴───────────────────────────────────────────────────────┘
17 findings | 7 CRITICAL | 8 HIGH | 2 MEDIUM | Duration: 1217ms
```

Every finding includes a **runnable Python PoC** and step-by-step remediation.

---

## What It Checks

7 checker categories, 21 sub-checks:

| Category | IDs | What it tests |
|----------|-----|---------------|
| **Price Manipulation** | PRICE-001..006 | Underpayment, decimal confusion, negative/zero amounts, integer overflow |
| **Session Replay** | SESS-001..004 | Token reuse, expired sessions, session ID swap, missing expiry |
| **Race Conditions** | RACE-001..002 | Parallel replay (10 concurrent requests), TOCTOU |
| **Overclaiming** | OVER-001..002 | Inconsistent pricing, unreasonable price thresholds |
| **Payment Verification** | VRFY-001..003 | Foreign txhash, underpaid tx, unconfirmed/pending tx |
| **Malicious 402** | INJ-001..002 | Invalid destination address format, bad EIP-55 checksum |
| **Denial of Service** | DOS-001..004 | Low delivery rate, timeout without refund, pay-and-no-deliver, recursive billing |

---

## Quick Start

### Option 1: Docker (recommended)

```bash
git clone https://github.com/Solitud1nem/mpp-scanner.git
cd mpp-scanner

cp .env.example .env
# Edit .env with your Tempo wallet and RPC details

docker compose up --build
```

Services start on:
- **API** — `http://localhost:8000`
- **Vuln target** (for testing) — `http://localhost:9000`
- **Redis** — `localhost:6379`
- **PostgreSQL** — `localhost:5432`

```bash
# Test it
curl http://localhost:8000/health
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" \
  -d '{"target":"http://target-vuln:9000/service"}'
# → 402 Payment Required (MPP flow working)
```

### Option 2: Local development

```bash
# Prerequisites: Python 3.12+, uv
uv sync

# Run all 31 tests
uv run pytest tests/ -v

# Start scanner in dev mode (no chain verification)
MPP_SKIP_CHAIN_VERIFY=1 uv run uvicorn mpp_scanner.service.app:app --port 8000

# Scan via CLI
uv run python -m cli.main http://localhost:8000/scan --tier full
```

---

## API

### MPP Payment Flow

```
Agent                          Scanner
  │                               │
  ├── POST /scan ────────────────►│
  │◄── 402 + payment headers ─────┤
  │                               │
  ├── Pay USDC on Tempo chain     │
  │                               │
  ├── POST /scan ────────────────►│
  │   X-Payment-Tx: 0xabc...     │
  │   X-Payment-Session: sess_.. │
  │◄── 200 + scan results ────────┤
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/scan` | MPP | Create a new vulnerability scan |
| `GET` | `/scan/{id}` | MPP | Poll async scan job status |
| `GET` | `/certificate/{target}` | Public | Read on-chain security certificate |
| `GET` | `/health` | Public | Health check |
| `GET` | `/.well-known/mpp-scanner` | Public | Service discovery & pricing |

### Pricing Tiers

| Tier | Price | What you get |
|------|-------|-------------|
| `quick` | $0.05 USDC | 3 critical categories (price, inject, session) |
| `full` | $0.25 USDC | All 7 categories, async queue |
| `certified` | $1.00 USDC | Full scan + on-chain security certificate (24h validity) |

### Output Formats

```bash
uv run python -m cli.main http://target --output stdout     # Rich table (default)
uv run python -m cli.main http://target --output json        # JSON
uv run python -m cli.main http://target --output markdown    # Markdown report
uv run python -m cli.main http://target --output sarif       # SARIF for CI/CD
```

---

## Smart Contract

`MPPSecurityCertificate` is live on **Tempo Moderato testnet**:

| | |
|---|---|
| **Contract** | [`0x8cF01fb57002CA878084cBFad43Ba105186BE722`](https://explore.moderato.tempo.xyz/address/0x8cF01fb57002CA878084cBFad43Ba105186BE722) |
| **Deploy tx** | [`0xacf0ffef...`](https://explore.moderato.tempo.xyz/tx/0xacf0ffef06552ecd060df9991aa388041579534f4e8ea549a546339da1f3d620) |
| **Chain** | Tempo Moderato (ID: 42431) |
| **RPC** | `https://rpc.moderato.tempo.xyz` |

**Functions:**
- `issue(target, scanId, hasCritical)` — mint a 24h security certificate (scanner wallet only)
- `isValid(target) → bool` — check if target has a valid, non-critical certificate
- `getCertificate(target)` — read full certificate data

```bash
# Verify on-chain
cast call --rpc-url https://rpc.moderato.tempo.xyz \
  0x8cF01fb57002CA878084cBFad43Ba105186BE722 \
  "isValid(address)(bool)" 0x0000000000000000000000000000000000000001
# → true

# Run Foundry tests (12/12 passing)
cd contracts && forge test -v
```

---

## Architecture

```
mpp-scanner/
├── mpp_scanner/                 # Core Python package
│   ├── models.py                # Finding, Severity, ScanResult, PaymentInfo
│   ├── discovery.py             # Fingerprint MPP endpoints (parse 402 headers)
│   ├── engine.py                # Async parallel checker orchestrator
│   ├── poc.py                   # PoC code generator (templates for all 21 checks)
│   ├── reporter.py              # JSON, Markdown, SARIF output
│   ├── checks/                  # 7 independent checker modules
│   │   ├── base.py              # BaseChecker ABC
│   │   ├── price.py             # PRICE-001..006
│   │   ├── session.py           # SESS-001..004
│   │   ├── race.py              # RACE-001..002
│   │   ├── overclaim.py         # OVER-001..002
│   │   ├── verify.py            # VRFY-001..003
│   │   ├── inject.py            # INJ-001..002
│   │   └── dos.py               # DOS-001..004
│   └── service/                 # FastAPI HTTP service
│       ├── app.py               # App factory, Redis lifespan
│       ├── middleware.py         # MPP 402 payment gate
│       ├── verifier.py          # Payment txhash verification
│       ├── chain.py             # web3.py ↔ Tempo RPC
│       ├── cache.py             # Redis scan cache (TTL per tier)
│       ├── scheduler.py         # RQ async job queue
│       └── routers/             # scan, certificate, health
├── contracts/
│   ├── src/SecurityCertificate.sol
│   ├── test/SecurityCertificate.t.sol
│   └── foundry.toml
├── cli/main.py                  # Typer CLI (mpp-scan)
├── tests/                       # 31 Python tests
│   ├── fixtures/                # Clean + vulnerable mock MPP servers
│   ├── test_checkers/           # Per-checker tests (7 files)
│   └── test_integration/        # Service + full flow tests
├── Dockerfile
├── docker-compose.yml           # api + 3x worker + redis + postgres + vuln-target
└── .env.example
```

---

## Testing

```
43 tests total — 31 Python, 12 Solidity — all passing
```

```bash
# Python tests
uv run pytest tests/ -v
# 31 passed

# Solidity tests
cd contracts && forge test -v
# 12 passed

# Coverage (checker code: 83–100%)
uv run pytest tests/ --cov=mpp_scanner --cov-report=term-missing
```

**Sybil test** — the core correctness guarantee:
1. All checkers vs `mock_mpp_server.py` (correctly implemented) → **0 findings**
2. All checkers vs `vuln_mpp_server.py` (intentionally broken) → **17 findings across all 7 categories**

---

## Security Model

| Layer | Mechanism |
|-------|-----------|
| **Session replay** | Redis `SETNX` with 300s TTL — atomic, single-use |
| **Payment double-spend** | Redis `SETNX` with 86400s TTL — txhash can only be used once |
| **On-chain verification** | web3.py verifies recipient, amount, and confirmation count |
| **Certificate trust** | `onlyScanner` modifier — only the scanner wallet can issue certs |
| **Fallback** | In-memory dicts when Redis unavailable (dev/test) |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TEMPO_RPC_URL` | Yes | Tempo chain RPC (`https://rpc.moderato.tempo.xyz`) |
| `SCANNER_WALLET_ADDRESS` | Yes | Scanner's wallet address |
| `SCANNER_WALLET_PRIVATE_KEY` | Yes | Private key for cert minting (**never commit**) |
| `CERTIFICATE_CONTRACT_ADDRESS` | No | Deployed SecurityCertificate address |
| `REDIS_URL` | No | Redis connection (default: `redis://localhost:6379/0`) |
| `DATABASE_URL` | No | PostgreSQL connection |
| `MPP_SKIP_CHAIN_VERIFY` | No | Set `1` for dev mode (skip on-chain checks) |

See [`.env.example`](.env.example) for a complete template.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI, uvicorn, Python 3.12 |
| Package manager | uv |
| Async queue | Redis + RQ |
| Database | PostgreSQL |
| Blockchain | web3.py → Tempo RPC |
| Contracts | Solidity 0.8.20, Foundry |
| CLI | Typer + Rich |
| Deploy | Docker Compose |

---

## License

MIT
