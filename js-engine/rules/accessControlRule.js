class AccessControlRule {

  analyze(ast, filePath) {

    const findings = [];

    if (!ast || !ast.program || !ast.program.body) {
      return findings;
    }

    const expressMethods = ["get", "post", "put", "delete", "patch"];

    let routerNames = new Set();
    let mountedRouters = {}; // routerName -> basePath

    /* ===================================== */
    /* 1️⃣ Detect Router Declarations         */
    /* ===================================== */

    ast.program.body.forEach(node => {

      // const router = express.Router()
      if (
        node.type === "VariableDeclaration"
      ) {
        node.declarations.forEach(decl => {
          if (
            decl.init &&
            decl.init.callee &&
            decl.init.callee.property &&
            decl.init.callee.property.name === "Router"
          ) {
            routerNames.add(decl.id.name);
          }
        });
      }
    });

    /* ===================================== */
    /* 2️⃣ Detect app.use("/base", router)   */
    /* ===================================== */

    ast.program.body.forEach(node => {

      if (
        node.type === "ExpressionStatement" &&
        node.expression &&
        node.expression.callee &&
        node.expression.callee.property &&
        node.expression.callee.property.name === "use"
      ) {

        const args = node.expression.arguments;

        if (args.length === 2 &&
            args[0].type === "StringLiteral" &&
            args[1].type === "Identifier"
        ) {
          mountedRouters[args[1].name] = args[0].value;
        }
      }
    });

    /* ===================================== */
    /* 3️⃣ Detect Routes (app + router)       */
    /* ===================================== */

    ast.program.body.forEach(node => {

      if (
        node.type === "ExpressionStatement" &&
        node.expression &&
        node.expression.callee &&
        node.expression.callee.property &&
        expressMethods.includes(node.expression.callee.property.name)
      ) {

        const method = node.expression.callee.property.name;
        const caller = node.expression.callee.object.name;
        const args = node.expression.arguments;

        if (!args || args.length < 2) return;
        if (args[0].type !== "StringLiteral") return;

        let routePath = args[0].value;

        // If route belongs to mounted router → prefix it
        if (mountedRouters[caller]) {
          routePath = mountedRouters[caller] + routePath;
        }

        const handlerNode = args[1];

        let handlerCode = "";
        if (handlerNode.body && handlerNode.body.body) {
          handlerCode = handlerNode.body.body
            .map(n => JSON.stringify(n))
            .join(" ");
        }

        const isParamRoute = routePath.includes(":");

        /* ===================================== */
        /* Missing Authorization Detection       */
        /* ===================================== */

        const hasAuthCheck =
          handlerCode.includes("isAuthenticated") ||
          handlerCode.includes("isAdmin") ||
          handlerCode.includes("req.user") ||
          handlerCode.includes("verify") ||
          handlerCode.includes("jwt");

        if (!hasAuthCheck) {
          findings.push({
            file: filePath,
            type: "Missing Authorization Check",
            line: node.loc ? node.loc.start.line : 0,
            routePath,
            routeMethod: method
          });
        }

        /* ===================================== */
        /* IDOR Detection                        */
        /* ===================================== */

        const usesUserInput =
          handlerCode.includes("req.params") ||
          handlerCode.includes("req.body") ||
          handlerCode.includes("req.query");

        const dbAccessPatterns = [
          "findByPk",
          "findById",
          "findOne",
          "where",
          "update",
          "destroy"
        ];

        const usesDB = dbAccessPatterns.some(pattern =>
          handlerCode.includes(pattern)
        );

        const hasOwnershipCheck =
          handlerCode.includes("req.user.id") ||
          handlerCode.includes("ownerId") ||
          handlerCode.includes("=== req.user");

        if (isParamRoute && usesUserInput && usesDB && !hasOwnershipCheck) {
          findings.push({
            file: filePath,
            type: "Insecure Direct Object Reference",
            line: node.loc ? node.loc.start.line : 0,
            routePath,
            routeMethod: method
          });
        }
      }
    });

    return findings;
  }
}

module.exports = AccessControlRule;
