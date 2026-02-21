const traverse = require("@babel/traverse").default;
const BaseRule = require("./baseRule");

class XSSRule extends BaseRule {
  constructor() {
    super("XSSRule");
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

      if (node.type === "ObjectExpression") {
        return node.properties.some(prop =>
          containsTainted(prop.value)
        );
      }

      if (node.type === "MemberExpression") {
        return containsTainted(node.object);
      }

      return false;
    }

    traverse(ast, {

      /* ===== Source Tracking ===== */
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

      /* ===== XSS Sink Detection ===== */
      CallExpression(path) {
        if (
          path.node.callee.type === "MemberExpression"
        ) {
          const method =
            path.node.callee.property.name;

          if (
            ["send", "render", "json"].includes(method)
          ) {
            path.node.arguments.forEach(arg => {
              if (containsTainted(arg)) {
                findings.push({
                  file: filePath,
                  type: "Cross-Site Scripting (XSS)",
                  line:
                    path.node.loc?.start?.line || 0
                });
              }
            });
          }
        }
      }
    });

    return findings;
  }
}

module.exports = XSSRule;
