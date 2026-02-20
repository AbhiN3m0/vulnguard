import ast


class PythonASTScanner(ast.NodeVisitor):
    def __init__(self, rules, file_path):
        self.rules = rules
        self.file_path = file_path
        self.findings = []
        self.tainted_vars = set()
        self.current_function = None

    # ---------------------------------------------------
    # Function Scope Handling
    # ---------------------------------------------------
    def visit_FunctionDef(self, node):
        self.tainted_vars = set()
        self.current_function = node.name

        # Mark function parameters as tainted
        for arg in node.args.args:
            self.tainted_vars.add(arg.arg)

        self.generic_visit(node)

    # ---------------------------------------------------
    # Assignment + Sanitizer Handling
    # ---------------------------------------------------
    def visit_Assign(self, node):
        value_is_tainted = self._is_tainted(node.value)

        # If assignment is sanitizer call → clean value
        if isinstance(node.value, ast.Call):
            call_name = self._resolve_full_name(node.value.func)
            if self._is_sanitizer(call_name):
                value_is_tainted = False

        for target in node.targets:
            if isinstance(target, ast.Name):
                if value_is_tainted:
                    self.tainted_vars.add(target.id)
                else:
                    self.tainted_vars.discard(target.id)

        self.generic_visit(node)

    # ---------------------------------------------------
    # Function Call Detection (Sinks)
    # ---------------------------------------------------
    def visit_Call(self, node):
        full_name = self._resolve_full_name(node.func)

        if not full_name:
            self.generic_visit(node)
            return

        for rule in self.rules:
            if rule.get("language") != "python":
                continue

            if rule.get("type") != "function_call":
                continue

            if full_name != rule.get("name"):
                continue

            arg_index = rule.get("argument_index", 0)
            taint_required = rule.get("taint_required", False)
            detect_sql_string = rule.get("detect_sql_string", False)

            if len(node.args) <= arg_index:
                continue

            target_arg = node.args[arg_index]
            exploitable = False

            # --------------------------------------------
            # 1️⃣ Taint-based detection
            # --------------------------------------------
            if taint_required and self._is_tainted(target_arg):
                exploitable = True

            # --------------------------------------------
            # 2️⃣ Dynamic SQL detection
            # --------------------------------------------
            if detect_sql_string and self._is_dynamic_sql(target_arg):
                exploitable = True

            # --------------------------------------------
            # 3️⃣ Safe parameterized query detection
            # --------------------------------------------
            if detect_sql_string and len(node.args) > 1:
                exploitable = False

            # Skip non-exploitable SQL sinks (precision mode)
            if detect_sql_string and not exploitable:
                continue

            self.findings.append({
                "rule_id": rule.get("id"),
                "title": rule.get("message"),
                "severity": rule.get("severity"),
                "owasp": rule.get("owasp"),
                "file": self.file_path,
                "line": node.lineno,
                "code": f"{full_name}(...)",
                "recommendation": rule.get("fix"),
                "exploitable": exploitable,
                "confidence": "High" if exploitable else "Low"
            })

        self.generic_visit(node)

    # ---------------------------------------------------
    # Resolve full dotted attribute name
    # ---------------------------------------------------
    def _resolve_full_name(self, node):
        if isinstance(node, ast.Name):
            return node.id

        elif isinstance(node, ast.Attribute):
            parent = self._resolve_full_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr

        elif isinstance(node, ast.Call):
            return self._resolve_full_name(node.func)

        return None

    # ---------------------------------------------------
    # Rule-driven source detection
    # ---------------------------------------------------
    def _is_source(self, name):
        for rule in self.rules:
            sources = rule.get("sources", [])
            if name in sources:
                return True
        return False

    # ---------------------------------------------------
    # Rule-driven sanitizer detection
    # ---------------------------------------------------
    def _is_sanitizer(self, name):
        for rule in self.rules:
            sanitizers = rule.get("sanitizers", [])
            if name in sanitizers:
                return True
        return False

    # ---------------------------------------------------
    # Taint Propagation Engine
    # ---------------------------------------------------
    def _is_tainted(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars

        elif isinstance(node, ast.Call):
            name = self._resolve_full_name(node.func)

            # Source detection
            if self._is_source(name):
                return True

            # Sanitizer cleans
            if self._is_sanitizer(name):
                return False

            # Propagate from arguments
            return any(self._is_tainted(arg) for arg in node.args)

        elif isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)

        elif isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if self._is_tainted(value.value):
                        return True
            return False

        return False

    # ---------------------------------------------------
    # Dynamic SQL Detection
    # ---------------------------------------------------
    def _is_dynamic_sql(self, node):
        # String concatenation
        if isinstance(node, ast.BinOp):
            return True

        # f-string
        if isinstance(node, ast.JoinedStr):
            return True

        # .format() usage
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "format":
                    return True

        return False


# -------------------------------------------------------
# Public Scanner Entry
# -------------------------------------------------------
def scan_python_file(file_path, rules):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source, filename=file_path)

        scanner = PythonASTScanner(rules, file_path)
        scanner.visit(tree)

        return scanner.findings

    except Exception:
        return []

