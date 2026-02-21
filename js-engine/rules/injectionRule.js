const traverse = require("@babel/traverse").default;
const BaseRule = require("./baseRule");

class InjectionRule extends BaseRule {
  constructor() {
    super("InjectionRule");
  }

  analyze(ast, filePath, mode) {
    const findings = [];
    const taintedVars = new Set();

    function isReqSource(node) {
      if (!node) return false;

      if (node.type === "Identifier" && node.name === "req") {
        return true;
      }

      if (node.type === "MemberExpression") {
        return isReqSource(node.object);
      }

      return false;
    }

    function containsTainted(node) {
      if (!node) return false;

      if (node.type === "Identifier") {
        return taintedVars.has(node.name);
      }

      if (node.type === "BinaryExpression") {
        return (
          containsTainted(node.left) ||
          containsTainted(node.right)
        );
      }

      if (node.type === "TemplateLiteral") {
        return node.expressions.some(expr =>
          containsTainted(expr)
        );
      }

      if (node.type === "MemberExpression") {
        return containsTainted(node.object);
      }

      return false;
    }

    traverse(ast, {
      VariableDeclarator(path) {
        const init = path.node.init;
        const id = path.node.id;

        if (!init) return;

        if (init.type === "MemberExpression" && isReqSource(init)) {
          if (id.type === "Identifier") {
            taintedVars.add(id.name);
          }
        }
      },

      CallExpression(path) {
        const callee =
          path.node.callee.type === "MemberExpression"
            ? path.node.callee.property.name
            : path.node.callee.name;

        if (!callee) return;

        if (["exec", "execSync", "spawn"].includes(callee)) {
          path.node.arguments.forEach(arg => {
            if (containsTainted(arg)) {
              findings.push({
                file: filePath,
                type: "Command Injection",
                line: path.node.loc?.start?.line || 0
              });
            }
          });
        }

        if (["query", "execute"].includes(callee)) {
          path.node.arguments.forEach(arg => {
            if (containsTainted(arg)) {
              findings.push({
                file: filePath,
                type: "SQL Injection",
                line: path.node.loc?.start?.line || 0
              });
            }
          });
        }
      }
    });

    return findings;
  }
}

module.exports = InjectionRule;
