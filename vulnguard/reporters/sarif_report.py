import json
from pathlib import Path


def export_sarif(findings, output_file="vulnguard-report.sarif"):
    sarif_output = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnGuard",
                        "informationUri": "https://github.com/AbhiN3m0/vulnguard",
                        "version": "0.4.0",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    rules_added = {}

    for finding in findings:

        rule_id = finding["rule_id"]

        if rule_id not in rules_added:
            sarif_output["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": finding["name"],
                "shortDescription": {
                    "text": finding["name"]
                },
                "fullDescription": {
                    "text": finding["recommendation"]
                },
                "properties": {
                    "severity": finding["severity"],
                    "owasp": finding["owasp"]
                }
            })
            rules_added[rule_id] = True

        sarif_output["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": severity_to_level(finding["severity"]),
            "message": {
                "text": f"{finding['name']} - {finding['recommendation']}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding["file"]
                        },
                        "region": {
                            "startLine": finding["line"]
                        }
                    }
                }
            ]
        })

    with open(output_file, "w") as f:
        json.dump(sarif_output, f, indent=2)

    print(f"\nSARIF report saved to {output_file}")


def severity_to_level(severity):
    severity = severity.upper()
    if severity == "HIGH":
        return "error"
    elif severity == "MEDIUM":
        return "warning"
    else:
        return "note"

