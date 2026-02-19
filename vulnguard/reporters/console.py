def print_report(findings, total_files):
    high = 0
    medium = 0
    low = 0

    for finding in findings:
        severity = finding["severity"].upper()

        if severity == "HIGH":
            high += 1
        elif severity == "MEDIUM":
            medium += 1
        else:
            low += 1

        print(f"\n[ {severity} ] {finding['name']}")
        print(f"File: {finding['file']}")
        print(f"Line: {finding['line']}")
        print(f"OWASP: {finding['owasp']}\n")

        print("Code:")
        print(finding["code"].strip(), "\n")

        print("Recommendation:")
        print(finding["recommendation"])

        # 🔥 AI Output Section
        if "ai" in finding:
            ai = finding["ai"]

            print("\n--- AI Security Analysis ---")
            print(f"AI Risk Level: {ai.get('risk_level')}")
            print(f"Exploitable: {ai.get('is_exploitable')}")
            print(f"Confidence: {ai.get('confidence')}\n")

            print("AI Reasoning:")
            print(ai.get("reasoning"))

            print("\nAI Secure Fix:")
            print(ai.get("secure_fix"))

        print("\n" + "-" * 50)

    print("\n========== Scan Summary ==========")
    print(f"Scanned Files: {total_files}")
    print(f"Total Findings: {len(findings)}")
    print(f"HIGH: {high}")
    print(f"MEDIUM: {medium}")
    print(f"LOW: {low}")
    print("==================================")

