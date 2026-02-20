import yaml
from pathlib import Path

RULE_SCHEMA_VERSION = 1


def load_rules(file_path: Path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("Invalid rule file format")

    file_schema_version = data.get("schema_version")

    if file_schema_version != RULE_SCHEMA_VERSION:
        raise ValueError(
            f"Rule schema version mismatch. "
            f"Expected {RULE_SCHEMA_VERSION}, got {file_schema_version}"
        )

    rules = data.get("rules", [])

    if not isinstance(rules, list):
        raise ValueError("Rules must be a list")

    return rules

