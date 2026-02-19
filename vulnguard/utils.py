def load_code_context(file_path, line_number, context=5):
    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()

        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)

        snippet = "".join(lines[start:end])
        return snippet

    except Exception:
        return ""

