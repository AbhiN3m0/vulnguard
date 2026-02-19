
from pathlib import Path
from vulnguard.matcher import match_rule


EXCLUDED_DIRS = {"venv", "__pycache__", "site-packages", ".git"}


def scan_directory(path, rules):
    findings = []

    for file in Path(path).rglob("*.py"):

        # Skip excluded directories
        if any(excluded in file.parts for excluded in EXCLUDED_DIRS):
            continue

        try:
            content = file.read_text(errors="ignore")
        except Exception:
            continue

        for rule in rules:
            if rule.language == "python":
                results = match_rule(rule, content)

                for result in results:
                    result["file"] = str(file)
                    findings.append(result)

    return findings

