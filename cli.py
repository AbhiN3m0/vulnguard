import typer
from pathlib import Path

from vulnguard.rule_loader import load_rules
from vulnguard.scanner import scan_directory
from vulnguard.reporters.console import print_report
from vulnguard.reporters.json_report import export_json

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
):
    """
    Scan a directory for security issues.
    """

    rule_dir = Path(__file__).parent / "rules"

    rules = []
    rules += load_rules(rule_dir / "python_owasp.yaml")
    rules += load_rules(rule_dir / "javascript_owasp.yaml")

    findings = scan_directory(path, rules)

    # Apply severity filter if provided
    if severity:
        findings = [
            f for f in findings
            if f["severity"].upper() == severity.upper()
        ]

    print_report(findings)

    if json_output:
        export_json(findings)


if __name__ == "__main__":
    app()

