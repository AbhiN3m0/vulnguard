import typer
from pathlib import Path

from vulnguard.rule_loader import load_rules
from vulnguard.scanner import scan_directory
from vulnguard.reporters.console import print_report
from vulnguard.reporters.json_report import export_json
from vulnguard.reporters.sarif_report import export_sarif

from vulnguard.ai.enrichment import enrich_findings
from vulnguard.utils import load_code_context

app = typer.Typer()


@app.command()
def main(
    path: str,
    severity: str = typer.Option(
        None,
        help="Filter by severity (LOW, MEDIUM, HIGH)"
    ),
    json_output: bool = typer.Option(
        False,
        help="Export results to JSON file"
    ),
    sarif_output: bool = typer.Option(
        False,
        help="Export results to SARIF file"
    ),
    ai: bool = typer.Option(
        False,
        help="Enable AI enrichment (local provider)"
    ),
):
    """
    Scan a directory for security issues.
    """

    rule_dir = Path(__file__).parent / "rules"

    rules = []
    rules += load_rules(rule_dir / "python_owasp.yaml")
    rules += load_rules(rule_dir / "javascript_owasp.yaml")

    findings, total_files = scan_directory(path, rules)

    # Apply severity filter
    if severity:
        findings = [
            f for f in findings
            if f["severity"].upper() == severity.upper()
        ]

    # AI enrichment (inside function only)
    if ai:
        findings = enrich_findings(
            findings,
            load_code_context,
            provider="local"
        )

    print_report(findings, total_files)

    if json_output:
        export_json(findings)

    if sarif_output:
        export_sarif(findings)


if __name__ == "__main__":
    app()

