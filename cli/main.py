from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console
from rich.table import Table

from mpp_scanner.engine import run_scan
from mpp_scanner.reporter import to_json, to_markdown, to_sarif

app = typer.Typer(name="mpp-scan", help="MPP Security Scanner CLI")
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(help="MPP service endpoint URL to scan"),
    tier: str = typer.Option("full", help="Scan tier: quick|full|certified"),
    output: str = typer.Option("stdout", help="Output format: stdout|json|markdown|sarif"),
    fail_on: str = typer.Option("critical", help="Exit non-zero on: critical|high|medium|none"),
) -> None:
    """Scan an MPP service endpoint for vulnerabilities."""
    result = asyncio.run(run_scan(target, tier))

    if output == "json":
        console.print(to_json(result))
    elif output == "markdown":
        console.print(to_markdown(result))
    elif output == "sarif":
        console.print(to_sarif(result))
    else:
        # Rich table output
        table = Table(title=f"Scan: {target}")
        table.add_column("ID", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Title")

        for f in result.findings:
            table.add_row(f.id, f.severity.value, f.title)

        console.print(table)
        console.print(
            f"\n[bold]{len(result.findings)} findings[/bold] "
            f"| Scan ID: {result.scan_id} "
            f"| Duration: {result.duration_ms}ms"
        )

    # Exit codes
    if fail_on == "critical" and result.has_critical:
        raise typer.Exit(3)
    elif fail_on == "high" and result.has_high:
        raise typer.Exit(2)
    elif fail_on == "medium" and any(
        f.severity.value in ("CRITICAL", "HIGH", "MEDIUM") for f in result.findings
    ):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
