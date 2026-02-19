import json


def export_json(findings, output_file="vulnguard-report.json"):
    with open(output_file, "w") as f:
        json.dump(findings, f, indent=4)

    print(f"JSON report saved to {output_file}")

