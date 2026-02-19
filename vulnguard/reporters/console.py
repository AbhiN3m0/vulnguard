def print_report(findings):
    if not findings:
        print("✅ No vulnerabilities found.")
        return

    for finding in findings:
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

