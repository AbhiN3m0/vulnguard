import re

IGNORE_COMMENT = "vulnguard: ignore"


def match_rule(rule, file_content):
    findings = []

    for line_number, line in enumerate(file_content.split("\n"), start=1):

        # Skip ignored lines
        if IGNORE_COMMENT in line:
            continue

        if re.search(rule.pattern, line):
            findings.append({
                "rule_id": rule.id,
                "name": rule.name,
                "line": line_number,
                "severity": rule.severity,
                "owasp": rule.owasp,
                "recommendation": rule.recommendation,
                "code": line.strip()
            })

    return findings

