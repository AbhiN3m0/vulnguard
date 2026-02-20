from tree_sitter import Language, Parser
import tree_sitter_javascript


class JavaScriptASTScanner:
    def __init__(self, file_path, rules):
        self.file_path = file_path
        self.rules = rules
        self.findings = []

        # Proper 0.23.x initialization
        self.parser = Parser()
        self.parser.language = Language(tree_sitter_javascript.language())

    def scan(self):
        try:
            with open(self.file_path, "rb") as f:
                code = f.read()
        except Exception:
            return []

        tree = self.parser.parse(code)
        root = tree.root_node
        self.visit(root, code)
        return self.findings

    def visit(self, node, code):
        if node.type == "assignment_expression":
            self.handle_assignment(node, code)

        if node.type == "call_expression":
            self.handle_call(node, code)

        for child in node.children:
            self.visit(child, code)

    def handle_assignment(self, node, code):
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")

        if not left or not right:
            return

        left_text = self.get_text(left, code)
        right_text = self.get_text(right, code)

        if left_text.endswith(".innerHTML"):
            rule = self.get_rule("JS-INNERHTML-003")
            if rule:
                self.add_finding(rule, node, f"{left_text} = {right_text}")

    def handle_call(self, node, code):
        function_node = node.child_by_field_name("function")
        if not function_node:
            return

        function_name = self.get_text(function_node, code)

        if function_name == "eval":
            rule = self.get_rule("JS-EVAL-001")
            if rule:
                self.add_finding(rule, node, self.get_text(node, code))

        if function_name == "document.write":
            rule = self.get_rule("JS-DOCUMENT-WRITE-002")
            if rule:
                self.add_finding(rule, node, self.get_text(node, code))

    def add_finding(self, rule, node, snippet):
        self.findings.append({
            "rule_id": rule["id"],
            "title": rule["message"],
            "severity": rule["severity"],
            "owasp": rule["owasp"],
            "file": self.file_path,
            "line": node.start_point[0] + 1,
            "code": snippet,
            "recommendation": rule["fix"],
            "exploitable": True,
            "confidence": "High"
        })

    def get_text(self, node, code):
        return code[node.start_byte:node.end_byte].decode("utf-8")

    def get_rule(self, rule_id):
        for rule in self.rules:
            if rule["id"] == rule_id:
                return rule
        return None


def scan_javascript_file(file_path, rules):
    scanner = JavaScriptASTScanner(file_path, rules)
    return scanner.scan()
