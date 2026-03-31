# MPP Security Scanner — Project Blueprint for Claude Code

## What we are building

MPP Security Scanner is the first vulnerability scanner for MPP (Machine Payment Protocol) services on the Tempo L1 blockchain. The scanner itself IS an MPP service: an agent pays $0.05–1.00 USDC to audit any other MPP endpoint.

**Core idea:** Before an agent pays a service, it first pays our scanner $0.05, gets a security report, then decides whether to proceed.

**Why this matters:** No competitor exists. Sardis Guard only does ML scoring on completed transactions (reactive). We do proactive testing before any money moves.

---

## Environment

- OS: Windows 11, WSL2 Ubuntu 24.04
- Python: 3.12 via `/mnt/d/Recon/.venv` (existing venv with Slither, Foundry)
- Package manager: `uv` (preferred over pip)
- Working directory: `D:\mpp-scanner\` (= `/mnt/d/mpp-scanner/` in WSL)
- Existing tools: Foundry 1.5.1, Slither 0.11.5, web3.py available

**Always use WSL2 for running commands. Never run Python directly on Windows cmd.**

---

## Tech Stack

- **Backend:** FastAPI + uvicorn, Python 3.12, uv for deps
- **Queue:** Redis + RQ (async scan jobs >5s)
- **DB:** PostgreSQL (scan history, subscriptions, billing)
- **Chain:** web3.py → Tempo RPC (payment verify + cert mint)
- **Contracts:** Solidity + Foundry (SecurityCertificate.sol)
- **Deploy:** Docker Compose

---

## Project Structure (build exactly this)

```
mpp-scanner/
├── CLAUDE.md                    # this file
├── pyproject.toml               # uv project config
├── .env.example                 # env vars template (never .env itself)
├── docker-compose.yml           # api + worker + redis + postgres
├── Dockerfile
│
├── mpp_scanner/                 # main Python package
│   ├── __init__.py
│   ├── models.py                # Finding, Severity, ScanResult, PaymentInfo, PoC
│   ├── discovery.py             # fingerprint MPP endpoint, parse 402 headers
│   ├── engine.py                # asyncio parallel checker runner
│   ├── poc.py                   # PoC Python code generator per finding
│   ├── reporter.py              # JSON, Markdown, SARIF output formats
│   │
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── base.py              # BaseChecker ABC
│   │   ├── price.py             # PriceManipulationChecker (PRICE-001..006)
│   │   ├── session.py           # SessionReplayChecker (SESS-001..004)
│   │   ├── race.py              # RaceConditionChecker (RACE-001..002)
│   │   ├── overclaim.py         # OverclaimingChecker (OVER-001..002)
│   │   ├── verify.py            # PaymentVerificationChecker (VRFY-001..003)
│   │   ├── inject.py            # Malicious402Checker (INJ-001..002)
│   │   └── dos.py               # DoSChecker (DOS-001..004)
│   │
│   └── service/                 # HTTP service layer
│       ├── app.py               # FastAPI app, lifespan, routers
│       ├── middleware.py        # MPPPricingMiddleware (402 flow)
│       ├── chain.py             # web3.py wrapper for Tempo RPC
│       ├── verifier.py          # payment txhash verification
│       ├── cache.py             # Redis cache layer, TTL strategy
│       ├── scheduler.py         # RQ job scheduler
│       └── routers/
│           ├── scan.py          # POST /scan, GET /scan/{id}
│           ├── certificate.py   # GET /certificate/{target}
│           └── health.py        # GET /health, /.well-known/mpp-scanner
│
├── contracts/
│   ├── src/
│   │   └── SecurityCertificate.sol
│   ├── test/
│   │   └── SecurityCertificate.t.sol
│   └── foundry.toml
│
├── tests/
│   ├── fixtures/
│   │   ├── mock_mpp_server.py   # clean MPP server for testing
│   │   └── vuln_mpp_server.py   # intentionally vulnerable server
│   ├── test_checkers/
│   │   ├── test_price.py
│   │   ├── test_session.py
│   │   ├── test_race.py
│   │   ├── test_overclaim.py
│   │   ├── test_verify.py
│   │   ├── test_inject.py
│   │   └── test_dos.py
│   └── test_integration/
│       └── test_full_flow.py    # full payment → scan → result cycle
│
└── cli/
    └── main.py                  # mpp-scan CLI via typer
```

---

## Build Order (strict — do in this sequence)

### Step 1: Project initialization

```bash
cd /mnt/d/mpp-scanner
uv init --package mpp-scanner
uv add fastapi uvicorn httpx pydantic web3 redis rq typer rich asyncio
uv add --dev pytest pytest-asyncio pytest-httpx
```

### Step 2: Core data models (`mpp_scanner/models.py`)

Build these dataclasses first — everything else depends on them:

```python
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class PaymentInfo:
    """Parsed from 402 response headers"""
    amount: int           # in micro-USDC (6 decimals)
    currency: str         # "USDC"
    destination: str      # Tempo wallet address
    session_id: str       # X-Payment-Session header
    expires_at: int       # unix timestamp
    network: str          # "tempo-mainnet" or "tempo-testnet"
    scheme: str           # "mpp-v1"

@dataclass
class Finding:
    id: str               # e.g. "PRICE-001"
    title: str
    severity: Severity
    description: str
    evidence: dict        # raw proof data
    poc_code: str         # runnable Python exploit
    remediation: str      # how to fix

@dataclass
class ScanResult:
    target: str
    scan_id: str
    tier: str             # "quick" | "full" | "certified"
    findings: list[Finding]
    from_cache: bool
    scanned_at: int       # unix timestamp
    duration_ms: int

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == Severity.HIGH for f in self.findings)
```

### Step 3: Discovery (`mpp_scanner/discovery.py`)

Parse the 402 response from any MPP endpoint:

```python
import httpx
from .models import PaymentInfo

REQUIRED_HEADERS = [
    "X-Payment-Amount",
    "X-Payment-Currency",
    "X-Payment-Destination",
    "X-Payment-Session",
    "X-Payment-Expires",
    "X-Payment-Network",
]

async def fingerprint(target: str, client: httpx.AsyncClient) -> PaymentInfo:
    """Send GET to target, expect 402, parse payment headers."""
    resp = await client.get(target, timeout=10.0)
    
    if resp.status_code != 402:
        raise ValueError(f"Expected 402, got {resp.status_code}. Not an MPP service.")
    
    missing = [h for h in REQUIRED_HEADERS if h not in resp.headers]
    if missing:
        raise ValueError(f"Missing MPP headers: {missing}")
    
    return PaymentInfo(
        amount=int(resp.headers["X-Payment-Amount"]),
        currency=resp.headers["X-Payment-Currency"],
        destination=resp.headers["X-Payment-Destination"],
        session_id=resp.headers["X-Payment-Session"],
        expires_at=int(resp.headers["X-Payment-Expires"]),
        network=resp.headers.get("X-Payment-Network", "unknown"),
        scheme=resp.headers.get("X-Payment-Scheme", "mpp-v1"),
    )
```

### Step 4: BaseChecker (`mpp_scanner/checks/base.py`)

```python
from abc import ABC, abstractmethod
import httpx
from ..models import Finding, PaymentInfo

class BaseChecker(ABC):
    """All checkers inherit from this."""
    id: str  # e.g. "PRICE"
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    @abstractmethod
    async def run(self, target: str, info: PaymentInfo) -> list[Finding]:
        """Run all sub-checks. Return list of findings (empty = clean)."""
        ...
    
    async def probe(self, target: str, headers: dict = None) -> httpx.Response:
        """Send request to target with optional custom headers."""
        return await self.client.get(
            target,
            headers=headers or {},
            timeout=15.0,
        )
    
    def finding(self, sub_id: str, title: str, severity, desc: str,
                evidence: dict, remediation: str) -> Finding:
        from ..poc import generate_poc
        return Finding(
            id=f"{self.id}-{sub_id}",
            title=title,
            severity=severity,
            description=desc,
            evidence=evidence,
            poc_code=generate_poc(f"{self.id}-{sub_id}", evidence),
            remediation=remediation,
        )
```

### Step 5: All 8 checkers

Build each checker as a separate file. Each implements `run()` and returns findings.

#### `checks/price.py` — PriceManipulationChecker

Sub-checks to implement:
- **PRICE-001:** Send `amount - 1` (underpayment by 1 micro-USDC) → should reject
- **PRICE-002:** Send amount with 18 decimals instead of 6 → decimal confusion
- **PRICE-003:** Send `0.009999` float string → float representation attack
- **PRICE-004:** Send negative amount → should reject
- **PRICE-005:** Send zero amount → should reject
- **PRICE-006:** Send `2^256 - 1` → integer overflow

For each: probe with anomalous payment proof header `X-Payment-Tx: <fake_proof>`, check if server returns 200 (vulnerable) or 402/400 (safe).

#### `checks/session.py` — SessionReplayChecker

- **SESS-001:** Get valid session token, use it twice → second use should fail
- **SESS-002:** Use token after `expires_at` timestamp → should reject
- **SESS-003:** Use token issued for `session_id_A` in request with `session_id_B`
- **SESS-004:** Check if `expires_at` field is missing → vulnerability

#### `checks/race.py` — RaceConditionChecker

- **RACE-001:** `asyncio.gather(*[probe(target) for _ in range(10)])` with same payment proof → count 200 responses, >1 = vulnerable
- **RACE-002:** Send payment, immediately send 10 parallel requests before server processes → TOCTOU

#### `checks/overclaim.py` — OverclaimingChecker

- **OVER-001:** Compare declared amount in 402 vs actually charged (requires Tempo RPC read)
- **OVER-002:** Open session, make 10 requests, sum all charges vs declared price × 10

#### `checks/verify.py` — PaymentVerificationChecker

- **VRFY-001:** Send real but foreign txhash (different transaction) as payment proof
- **VRFY-002:** Send txhash of transaction with smaller amount
- **VRFY-003:** Send txhash of pending (unconfirmed) transaction

For VRFY checks: generate test transactions on Tempo testnet, use their hashes in wrong contexts.

#### `checks/inject.py` — Malicious402Checker

- **INJ-001:** MITM simulation — check if server validates `X-Payment-Destination` address format
- **INJ-002:** Send request with invalid EIP-55 checksum address → server should reject

#### `checks/dos.py` — DoSChecker

- **DOS-001:** Pay correctly, measure delivery rate over 20 requests
- **DOS-002:** Pay correctly, trigger timeout, check if refund mechanism exists
- **DOS-003:** Check `pay-and-no-deliver ratio` > 5% threshold
- **DOS-004:** Detect recursive billing: service A calls B calls C all charging same agent

### Step 6: Engine (`mpp_scanner/engine.py`)

```python
import asyncio
import httpx
from .models import ScanResult, PaymentInfo
from .checks import ALL_CHECKERS  # import all 8 checker classes

TIER_CHECKS = {
    "quick":     ["price", "inject", "session"],     # 3 critical
    "full":      "all",
    "certified": "all",
}

async def run_scan(target: str, tier: str = "full") -> ScanResult:
    async with httpx.AsyncClient() as client:
        info = await fingerprint(target, client)
        
        checks_to_run = ALL_CHECKERS if tier != "quick" else QUICK_CHECKERS
        
        # Run all checkers in parallel with 30s timeout each
        tasks = [checker(client).run(target, info) for checker in checks_to_run]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        findings = []
        for result in results:
            if isinstance(result, Exception):
                continue  # log but don't crash
            findings.extend(result)
        
        return ScanResult(
            target=target,
            scan_id=generate_scan_id(),
            tier=tier,
            findings=findings,
            from_cache=False,
            scanned_at=int(time()),
            duration_ms=...,
        )
```

### Step 7: Mock servers for testing (`tests/fixtures/`)

**`mock_mpp_server.py`** — clean, correct MPP server:
```python
# FastAPI server that correctly implements MPP protocol
# Returns proper 402 with all headers
# Validates payments properly
# Use for: testing that checkers don't produce false positives
```

**`vuln_mpp_server.py`** — intentionally vulnerable server:
```python
# Accepts underpayments (PRICE-001 should fire)
# Accepts replayed session tokens (SESS-001 should fire)
# Returns 200 for any txhash without verification (VRFY-001 should fire)
# Use for: confirming checkers detect real vulnerabilities
```

### Step 8: FastAPI service (`mpp_scanner/service/`)

#### `middleware.py` — MPP 402 flow

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import time, secrets

SCANNER_WALLET = "tempo1..."  # from env
PRICING = {
    "quick":     50_000,   # $0.05 in micro-USDC
    "full":     250_000,   # $0.25
    "certified": 1_000_000, # $1.00
    "cached":    10_000,   # $0.01
}

class MPPPricingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not request.url.path.startswith("/scan"):
            return await call_next(request)
        
        payment_tx = request.headers.get("X-Payment-Tx")
        if not payment_tx:
            tier = request.query_params.get("tier", "full")
            price = PRICING.get(tier, PRICING["full"])
            session_id = f"sess_{secrets.token_hex(16)}"
            
            return Response(
                status_code=402,
                headers={
                    "X-Payment-Scheme":      "mpp-v1",
                    "X-Payment-Amount":      str(price),
                    "X-Payment-Currency":    "USDC",
                    "X-Payment-Destination": SCANNER_WALLET,
                    "X-Payment-Session":     session_id,
                    "X-Payment-Expires":     str(int(time.time()) + 300),
                    "X-Payment-Network":     "tempo-mainnet",
                }
            )
        
        # Verify payment on Tempo chain
        await verify_payment(payment_tx, price)
        return await call_next(request)
```

#### `routers/scan.py`

```python
@router.post("/scan")
async def create_scan(target: str, tier: str = "full"):
    # Check cache first
    cached = await cache.get(target)
    if cached:
        return cached  # price: $0.01 (handled by middleware)
    
    # For long scans: return job_id, client polls /scan/{id}
    if tier in ("full", "certified"):
        job_id = await queue.enqueue(run_scan, target, tier)
        return {"scan_id": job_id, "status": "queued"}
    
    # Quick scan: synchronous
    result = await run_scan(target, tier)
    await cache.set(target, result)
    return result
```

### Step 9: Solidity contract (`contracts/src/SecurityCertificate.sol`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MPPSecurityCertificate {
    struct Certificate {
        address target;
        uint256 issuedAt;
        uint256 expiresAt;   // issuedAt + 86400 (24h)
        bytes32 scanId;
        uint8   scannerVersion;
        bool    hasCritical;
    }
    
    mapping(address => Certificate) public certificates;
    address public immutable SCANNER_WALLET;
    uint8 public constant VERSION = 1;
    
    event CertificateIssued(address indexed target, bytes32 scanId, bool hasCritical);
    
    constructor(address _scannerWallet) {
        SCANNER_WALLET = _scannerWallet;
    }
    
    modifier onlyScanner() {
        require(msg.sender == SCANNER_WALLET, "Only scanner can issue certs");
        _;
    }
    
    function issue(address target, bytes32 scanId, bool hasCritical)
        external onlyScanner
    {
        certificates[target] = Certificate({
            target:         target,
            issuedAt:       block.timestamp,
            expiresAt:      block.timestamp + 86400,
            scanId:         scanId,
            scannerVersion: VERSION,
            hasCritical:    hasCritical
        });
        emit CertificateIssued(target, scanId, hasCritical);
    }
    
    function isValid(address target) external view returns (bool) {
        Certificate memory c = certificates[target];
        return c.issuedAt > 0
            && block.timestamp < c.expiresAt
            && !c.hasCritical;
    }
    
    function getCertificate(address target) external view returns (Certificate memory) {
        return certificates[target];
    }
}
```

Write Foundry tests in `contracts/test/SecurityCertificate.t.sol`:
- Test issue() only callable by SCANNER_WALLET
- Test isValid() returns false after 24h
- Test isValid() returns false if hasCritical = true
- Test full lifecycle: issue → isValid → expire

### Step 10: docker-compose.yml

```yaml
services:
  api:
    build: .
    env_file: .env
    ports: ["8000:8000"]
    depends_on: [redis, postgres]
    command: uvicorn mpp_scanner.service.app:app --host 0.0.0.0 --port 8000

  worker:
    build: .
    env_file: .env
    command: rq worker scan-jobs
    depends_on: [redis]
    deploy:
      replicas: 3

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: mpp_scanner
      POSTGRES_USER: scanner
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes: [pgdata:/var/lib/postgresql/data]

volumes:
  pgdata:
```

### Step 11: CLI (`cli/main.py`)

```python
import typer
import asyncio
from rich.console import Console
from rich.table import Table
from mpp_scanner.engine import run_scan
from mpp_scanner.reporter import to_markdown, to_sarif

app = typer.Typer()
console = Console()

@app.command()
def scan(
    target: str,
    tier: str = typer.Option("full", help="quick|full|certified"),
    output: str = typer.Option("stdout", help="stdout|json|markdown|sarif"),
    fail_on: str = typer.Option("critical", help="critical|high|medium|none"),
):
    """Scan an MPP service endpoint for vulnerabilities."""
    result = asyncio.run(run_scan(target, tier))
    
    # Display findings
    table = Table(title=f"Scan: {target}")
    table.add_column("ID", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("Title")
    
    for f in result.findings:
        table.add_row(f.id, f.severity, f.title)
    
    console.print(table)
    
    # Exit codes: 0=clean, 1=medium+, 2=high+, 3=critical
    if fail_on == "critical" and result.has_critical:
        raise typer.Exit(3)

if __name__ == "__main__":
    app()
```

---

## Environment Variables (`.env.example`)

```env
# Tempo chain
TEMPO_RPC_URL=https://rpc.tempo.xyz
TEMPO_CHAIN_ID=1729
SCANNER_WALLET_ADDRESS=tempo1...
SCANNER_WALLET_PRIVATE_KEY=  # NEVER commit this

# Contract addresses (fill after deploy)
CERTIFICATE_CONTRACT_ADDRESS=

# Database
DATABASE_URL=postgresql://scanner:password@postgres:5432/mpp_scanner

# Redis
REDIS_URL=redis://redis:6379/0

# App
DEBUG=false
LOG_LEVEL=info
```

---

## Testing Strategy

```bash
# Run all tests
uv run pytest tests/ -v

# Run only checker tests
uv run pytest tests/test_checkers/ -v

# Run with coverage
uv run pytest tests/ --cov=mpp_scanner --cov-report=term-missing

# Target: >80% coverage on checker code
```

**Critical test: Sybil check on mock servers**
1. Run all checkers against `mock_mpp_server.py` → expect 0 findings
2. Run all checkers against `vuln_mpp_server.py` → expect findings for each vulnerability

---

## Rules for Claude Code

1. **Never hardcode private keys, wallet addresses, or RPC URLs** — always use env vars
2. **Never commit `.env`** — only `.env.example`
3. **Always add type hints** — use `from __future__ import annotations`
4. **Each checker is independent** — no checker imports another checker
5. **Tests first for checkers** — write the vulnerable mock server behavior, then the checker
6. **Async everywhere** — all IO operations must be `async/await`
7. **Fail safe** — if a checker raises an exception, log it and continue other checkers
8. **No real money** — use Tempo testnet for all development. Never use mainnet wallet keys.
9. **Ask before creating migrations** — DB schema changes need confirmation
10. **Run `uv run pytest` before marking any phase complete**

---

## Phase Completion Criteria

**Phase 1 complete when:**
- `uv run pytest tests/test_checkers/` passes with >80% coverage
- Both mock servers work (clean server = 0 findings, vuln server = findings on all 8 checkers)
- `from mpp_scanner.engine import run_scan` works in Python REPL

**Phase 2 complete when:**
- `curl http://localhost:8000/scan?target=http://localhost:9000` returns 402
- Full payment flow works end-to-end with test wallet on Tempo testnet
- `docker compose up` starts without errors

**Phase 3 complete when:**
- `forge test` passes in `contracts/` directory
- Contract deployed to Tempo testnet, address in `.env`
- `GET /certificate/{target}` returns valid JSON

---

## Current Status

All three phases complete.

### Phase 1 — Core Scanner (DONE)
- 7 checker categories (21 sub-checks), all tested against clean + vuln mock servers
- Clean server → 0 findings, vuln server → findings across all categories
- Checker coverage: 83-100%

### Phase 2 — FastAPI Service (DONE)
- MPP 402 payment flow with session tracking (Redis-backed, in-memory fallback)
- Atomic replay protection via Redis SETNX for sessions and txhashes
- `POST /scan`, `GET /scan/{id}`, `GET /health`, `GET /.well-known/mpp-scanner`
- Docker Compose: api + 3x worker + redis + postgres + vuln-target

### Phase 3 — Solidity Contract (DONE)
- Deployed to Tempo Moderato testnet (chain ID 42431)
- Contract: `0x8cF01fb57002CA878084cBFad43Ba105186BE722`
- RPC: `https://rpc.moderato.tempo.xyz`
- `issue()`, `isValid()`, `getCertificate()` verified on-chain
- `GET /certificate/{target}` reads from deployed contract

### Test Summary
- 31 Python tests (all passing)
- 12 Foundry tests (all passing)
- 43 total tests