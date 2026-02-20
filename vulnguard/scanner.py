import os

IGNORED_DIRS = {"venv", "node_modules", ".git", "__pycache__"}


def scan_directory(path, rules):
    findings = []
    scanned_files = 0

    for root, dirs, files in os.walk(path):
        # Remove ignored directories from traversal
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for file in files:
            file_path = os.path.join(root, file)

            # -----------------------------
            # Python Files
            # -----------------------------
            if file.endswith(".py"):
                scanned_files += 1
                try:
                    from vulnguard.ast_python import scan_python_file
                    relevant_rules = [
                        r for r in rules if r.get("language") == "python"
                    ]
                    file_findings = scan_python_file(file_path, relevant_rules)
                    findings.extend(file_findings)
                except Exception as e:
                    print("PYTHON parse error:", file_path)
                    print(e)

            # -----------------------------
            # JavaScript Files
            # -----------------------------
            elif file.endswith(".js"):
                scanned_files += 1
                try:
                    from vulnguard.ast_javascript import scan_javascript_file
                    relevant_rules = [
                        r for r in rules if r.get("language") == "javascript"
                    ]
                    file_findings = scan_javascript_file(file_path, relevant_rules)
                    findings.extend(file_findings)
                except Exception as e:
                    print("JS parse error:", file_path)
                    print(e)

    return findings, scanned_files
