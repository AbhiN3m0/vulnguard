def print_report(findings, total_files):
    high = 0
    medium = 0
    low = 0

    for finding in findings:
        severity = finding.get("severity", "UNKNOWN").upper()

        if severity == "HIGH":
            high += 1
        elif severity == "MEDIUM":
            medium += 1
        else:
            low += 1

        print(f"\n[ {severity} ] {finding.get('title')}")
        print(f"File: {finding.get('file')}")
        print(f"Line: {finding.get('line')}")
        print(f"OWASP: {finding.get('owasp')}\n")

        print(f"Code:\n{finding.get('code')}\n")
        print(f"Recommendation:\n{finding.get('recommendation')}")
        print("-" * 50)

    print("\n========== Scan Summary ==========")
    print(f"Scanned Files: {total_files}")
    print(f"Total Findings: {len(findings)}")
    print(f"HIGH: {high}")
    print(f"MEDIUM: {medium}")
    print(f"LOW: {low}")
    print("==================================")

