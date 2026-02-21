const traverse = require("@babel/traverse").default;
const BaseRule = require("./baseRule");

const ROUTE_METHODS = ["get", "post", "put", "delete"];
const AUTH_KEYWORDS = [
  "authenticate",
  "authorize",
  "verify",
  "isadmin",
  "checkauth",
  "auth",
  "jwt"
];

class AccessControlRule extends BaseRule {
  constructor() {
    super("AccessControlRule");
  }

  analyze(ast, filePath, mode) {
    const findings = [];
    let globalAuthDetected = false;

    /* ================= FIRST PASS: Detect Global Middleware ================= */

    traverse(ast, {
      CallExpression(path) {
        if (
          path.node.callee.type === "MemberExpression" &&
          path.node.callee.property &&
          path.node.callee.property.name === "use"
        ) {
          const args = path.node.arguments;

          const hasAuth = args.some(arg => {
            if (arg.type === "Identifier") {
              return AUTH_KEYWORDS.some(keyword =>
                arg.name.toLowerCase().includes(keyword)
              );
            }
            return false;
          });

          if (hasAuth) {
            globalAuthDetected = true;
          }
        }
      }
    });

    /* ================= SECOND PASS: Detect Routes ================= */

    traverse(ast, {
      CallExpression(path) {

if (
  path.node.callee.type === "MemberExpression" &&
  path.node.callee.object &&
  path.node.callee.object.type === "Identifier" &&
  ["app", "router"].includes(
    path.node.callee.object.name
  ) &&
  ROUTE_METHODS.includes(
    path.node.callee.property.name
  )
) {
          const routeMethod =
            path.node.callee.property.name.toLowerCase();

          const args = path.node.arguments;
          if (args.length < 1) return;

          /* ===== Extract Route Path ===== */

          let routePath = "";

          const routePathNode = args[0];

          if (routePathNode.type === "StringLiteral") {
            routePath = routePathNode.value.toLowerCase();
          }

          /* ===== Extract Inline Middleware ===== */

          const middlewares = args.slice(1);

          const hasInlineAuth = middlewares.some(mw => {
            if (mw.type === "Identifier") {
              return AUTH_KEYWORDS.some(keyword =>
                mw.name.toLowerCase().includes(keyword)
              );
            }

            if (
              mw.type === "CallExpression" &&
              mw.callee.type === "Identifier"
            ) {
              return AUTH_KEYWORDS.some(keyword =>
                mw.callee.name.toLowerCase().includes(keyword)
              );
            }

            return false;
          });

          /* ===== If no inline auth AND no global auth → flag ===== */

          if (!hasInlineAuth && !globalAuthDetected) {
            findings.push({
              file: filePath,
              type: "Missing Authorization Check",
              line: path.node.loc?.start?.line || 0,
              routePath,
              routeMethod
            });
          }
        }
      }
    });

    return findings;
  }
}

module.exports = AccessControlRule;
