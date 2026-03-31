from __future__ import annotations

import json
from dataclasses import asdict

from .models import ScanResult, Finding


def to_json(result: ScanResult) -> str:
    """Serialize scan result to JSON."""
    data = asdict(result)
    return json.dumps(data, indent=2, default=str)


def to_markdown(result: ScanResult) -> str:
    """Render scan result as Markdown report."""
    lines = [
        f"# MPP Security Scan Report",
        f"",
        f"**Target:** {result.target}",
        f"**Scan ID:** {result.scan_id}",
        f"**Tier:** {result.tier}",
        f"**Duration:** {result.duration_ms}ms",
        f"**Findings:** {len(result.findings)}",
        f"**Cached:** {result.from_cache}",
        f"",
    ]

    if not result.findings:
        lines.append("No vulnerabilities found.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")

    for f in sorted(result.findings, key=_severity_order):
        lines.extend([
            f"### [{f.severity.value}] {f.id}: {f.title}",
            f"",
            f"{f.description}",
            f"",
            f"**Remediation:** {f.remediation}",
            f"",
            f"<details><summary>PoC Code</summary>",
            f"",
            f"```python",
            f"{f.poc_code}",
            f"```",
            f"",
            f"</details>",
            f"",
        ])

    return "\n".join(lines)


def to_sarif(result: ScanResult) -> str:
    """Render scan result as SARIF v2.1.0."""
    rules = []
    results_list = []

    for f in result.findings:
        rule_id = f.id
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "help": {"text": f.remediation},
            "defaultConfiguration": {
                "level": _sarif_level(f),
            },
        })
        results_list.append({
            "ruleId": rule_id,
            "message": {"text": f.description},
            "level": _sarif_level(f),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": result.target},
                    }
                }
            ],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mpp-scanner",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results_list,
            }
        ],
    }

    return json.dumps(sarif, indent=2)


def _severity_order(f: Finding) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(f.severity.value, 5)


def _sarif_level(f: Finding) -> str:
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(f.severity.value, "note")
