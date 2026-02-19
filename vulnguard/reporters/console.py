def print_report(findings, total_files):
    if not findings:
        print("✅ No vulnerabilities found.")
        print(f"\nScanned Files: {total_files}")
        print("Findings: 0")
        return

    severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in findings:
        severity_count[finding["severity"].upper()] += 1

        print(f"""
[ {finding['severity']} ] {finding['name']}
File: {finding['file']}
Line: {finding['line']}
OWASP: {finding['owasp']}

Code:
{finding['code']}

Recommendation:
{finding['recommendation']}
----------------------------------------------------
""")

    print("\n========== Scan Summary ==========")
    print(f"Scanned Files: {total_files}")
    print(f"Total Findings: {len(findings)}")
    print(f"HIGH: {severity_count['HIGH']}")
    print(f"MEDIUM: {severity_count['MEDIUM']}")
    print(f"LOW: {severity_count['LOW']}")
    print("==================================")

