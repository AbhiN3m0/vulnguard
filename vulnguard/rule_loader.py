import yaml
from pathlib import Path
from vulnguard.models import Rule, RULE_SCHEMA_VERSION


def load_rules(rule_path: Path):
    with open(rule_path, "r") as f:
        data = yaml.safe_load(f)

    rules = []
    for item in data["rules"]:
        if item["schema_version"] != RULE_SCHEMA_VERSION:
            raise ValueError("Rule schema version mismatch")

        rules.append(Rule(**item))

    return rules

