IGNORE_COMMENT = "vulnguard: ignore"


def scan_file(file_path, rules):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line_number, line in enumerate(lines, start=1):

            # Skip ignored lines
            if IGNORE_COMMENT in line:
                continue

            for rule in rules:
                if rule.get("language") != "javascript":
                    continue

                pattern = rule.get("pattern")

                if pattern and pattern in line:
                    findings.append({
                        "rule_id": rule.get("id"),
                        "title": rule.get("message"),
                        "severity": rule.get("severity"),
                        "owasp": rule.get("owasp"),
                        "file": file_path,
                        "line": line_number,
                        "code": line.strip(),
                        "recommendation": rule.get("fix")
                    })

    except Exception:
        pass

    return findings

