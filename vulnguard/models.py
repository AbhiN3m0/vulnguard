from dataclasses import dataclass

RULE_SCHEMA_VERSION = "1.0"


@dataclass
class Rule:
    id: str
    name: str
    description: str
    pattern: str
    severity: str
    owasp: str
    recommendation: str
    language: str
    schema_version: str

