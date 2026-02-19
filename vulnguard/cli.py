import typer
from pathlib import Path

from vulnguard.rule_loader import load_rules
from vulnguard.scanner import scan_directory
from vulnguard.reporters.console import print_report
from vulnguard.reporters.json_report import export_json

app = typer.Typer()


@app.command()
def scan(path: str, json_output: bool = False):
    """
    Scan a directory for security issues.
    """

    rule_path = Path(__file__).parent / "rules" / "python_owasp.yaml"

    rules = load_rules(rule_path)

    findings = scan_directory(path, rules)

    print_report(findings)

    if json_output:
        export_json(findings)


if __name__ == "__main__":
    app()

