const traverse = require("@babel/traverse").default;

/*
  VulnGuard — Param Intelligence Engine
  Extracts:
  - Route path parameters
  - Regex route params
  - req.params / req.query / req.body usage
*/

function extractParamIntelligence(ast) {

  const routeParams = [];
  const paramUsage = [];

  traverse(ast, {

    /* ========================================== */
    /* Detect Express Route Params                */
    /* ========================================== */

    CallExpression(path) {

      const node = path.node;

      if (
        node.callee?.type === "MemberExpression" &&
        ["get", "post", "put", "delete", "patch"].includes(
          node.callee.property?.name
        )
      ) {

        const args = node.arguments;
        if (!args.length) return;

        /* ----- String route ----- */
        if (args[0].type === "StringLiteral") {

          const routePath = args[0].value;

          const params = [];
          const matches = routePath.match(/:([a-zA-Z0-9_]+)/g);

          if (matches) {
            matches.forEach(m => {
              params.push(m.replace(":", ""));
            });
          }

          if (params.length > 0) {
            routeParams.push({
              routePath,
              params,
              type: "express"
            });
          }

        }

        /* ----- Regex route ----- */
        if (args[0].type === "RegExpLiteral") {

          routeParams.push({
            routePath: args[0].pattern,
            params: ["regex_capture_group"],
            type: "regex"
          });

        }

      }

    },

    /* ========================================== */
    /* Detect req.params / req.query / req.body   */
    /* ========================================== */

    MemberExpression(path) {

      const node = path.node;

      if (
        node.object?.type === "MemberExpression" &&
        node.object.object?.name === "req"
      ) {

        const location = node.object.property?.name;
        const paramName = node.property?.name;

        if (["params", "query", "body"].includes(location)) {

          paramUsage.push({
            location,
            param: paramName
          });

        }

      }

    }

  });

  return {
    routeParams,
    paramUsage
  };
}

module.exports = { extractParamIntelligence };
