
from pathlib import Path
from vulnguard.matcher import match_rule


EXCLUDED_DIRS = {
    "venv",
    "__pycache__",
    "site-packages",
    ".git",
    "node_modules"
}

EXCLUDED_FILE_PATTERNS = {
    ".min.js"
}

SUPPORTED_EXTENSIONS = {
    "python": "*.py",
    "javascript": "*.js",
}


def scan_directory(path, rules):
    findings = []
    scanned_files = set()

    for rule in rules:
        pattern = SUPPORTED_EXTENSIONS.get(rule.language)

        if not pattern:
            continue

        for file in Path(path).rglob(pattern):

            if any(excluded in file.parts for excluded in EXCLUDED_DIRS):
                continue

            if any(file.name.endswith(pattern) for pattern in EXCLUDED_FILE_PATTERNS):
                continue

            scanned_files.add(str(file))

            try:
                content = file.read_text(errors="ignore")
            except Exception:
                continue

            results = match_rule(rule, content)

            for result in results:
                result["file"] = str(file)
                findings.append(result)

    return findings, len(scanned_files)

