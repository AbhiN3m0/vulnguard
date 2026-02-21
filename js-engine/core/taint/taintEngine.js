const traverse = require("@babel/traverse").default;

/* ================= SINK CONFIG ================= */

const COMMAND_SINKS = ["exec", "execSync", "spawn"];
const SQL_SINKS = ["query", "execute"];
const XSS_SINKS = ["send", "render"];

const ROUTE_METHODS = ["get", "post", "put", "delete"];
const AUTH_KEYWORDS = [
  "authenticate",
  "authorize",
  "verify",
  "isAdmin",
  "checkAuth",
  "auth",
  "jwt"
];

/* ================= SOURCE DETECTION ================= */

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

/* ================= RECURSIVE TAINT CHECK ================= */

function containsTainted(node, taintedVars) {
  if (!node) return false;

  if (node.type === "Identifier") {
    return taintedVars.has(node.name);
  }

  if (node.type === "BinaryExpression") {
    return (
      containsTainted(node.left, taintedVars) ||
      containsTainted(node.right, taintedVars)
    );
  }

  if (node.type === "TemplateLiteral") {
    return node.expressions.some(expr =>
      containsTainted(expr, taintedVars)
    );
  }

  if (node.type === "MemberExpression") {
    return containsTainted(node.object, taintedVars);
  }

  return false;
}

/* ================= MAIN ENGINE ================= */

function trackTaint(ast, mode = "practical") {
  const taintedVars = new Set();
  const findings = [];

  traverse(ast, {

    /* ===== Detect Sources ===== */
    VariableDeclarator(path) {
      const init = path.node.init;
      const id = path.node.id;

      if (!init) return;

      if (init.type === "MemberExpression" && isReqSource(init)) {
        if (id.type === "Identifier") {
          taintedVars.add(id.name);
        }
      }

      if (
        init.type === "Identifier" &&
        taintedVars.has(init.name)
      ) {
        if (id.type === "Identifier") {
          taintedVars.add(id.name);
        }
      }

      // Destructuring
      if (
        id.type === "ObjectPattern" &&
        init.type === "MemberExpression" &&
        isReqSource(init)
      ) {
        id.properties.forEach(prop => {
          if (prop.key && prop.key.name) {
            taintedVars.add(prop.key.name);
          }
        });
      }
    },

    AssignmentExpression(path) {
      const right = path.node.right;
      const left = path.node.left;

      if (
        right.type === "Identifier" &&
        taintedVars.has(right.name) &&
        left.type === "Identifier"
      ) {
        taintedVars.add(left.name);
      }
    },

    /* ===== Detect Sinks ===== */
    CallExpression(path) {
      let calleeName = "";

      if (path.node.callee.type === "Identifier") {
        calleeName = path.node.callee.name;
      }

      if (
        path.node.callee.type === "MemberExpression" &&
        path.node.callee.property
      ) {
        calleeName = path.node.callee.property.name;
      }

      /* ---- Command Injection ---- */
      if (COMMAND_SINKS.includes(calleeName)) {
        path.node.arguments.forEach(arg => {
          if (containsTainted(arg, taintedVars)) {
            findings.push({
              type: "Command Injection",
              line: path.node.loc?.start?.line || 0
            });
          }
        });
      }

      /* ---- SQL Injection ---- */
      if (SQL_SINKS.includes(calleeName)) {
        path.node.arguments.forEach(arg => {
          if (containsTainted(arg, taintedVars)) {
            findings.push({
              type: "SQL Injection",
              line: path.node.loc?.start?.line || 0
            });
          }
        });
      }

      /* ---- XSS ---- */
      if (XSS_SINKS.includes(calleeName)) {
        path.node.arguments.forEach(arg => {
          if (containsTainted(arg, taintedVars)) {
            findings.push({
              type: "Cross-Site Scripting (XSS)",
              line: path.node.loc?.start?.line || 0
            });
          }
        });
      }

      /* ================= EXPRESS ROUTE ANALYSIS ================= */

      if (
        path.node.callee.type === "MemberExpression" &&
        ROUTE_METHODS.includes(calleeName)
      ) {
        const args = path.node.arguments;

        if (args.length >= 2) {
          const routePath = args[0];
          const middlewares = args.slice(1);

          const hasAuth = middlewares.some(mw => {
            if (mw.type === "Identifier") {
              return AUTH_KEYWORDS.some(keyword =>
                mw.name.toLowerCase().includes(keyword.toLowerCase())
              );
            }

            if (mw.type === "CallExpression" && mw.callee.type === "Identifier") {
              return AUTH_KEYWORDS.some(keyword =>
                mw.callee.name.toLowerCase().includes(keyword.toLowerCase())
              );
            }

            return false;
          });

          if (!hasAuth) {
            findings.push({
              type: "Missing Authorization Check",
              line: path.node.loc?.start?.line || 0
            });
          }
        }
      }
    }
  });

  return findings;
}

module.exports = { trackTaint };
