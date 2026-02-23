const fs = require("fs");
const path = require("path");
const { parseCode } = require("../parser/astParser");

/*
  VulnGuard — Advanced Mount Graph Engine (Require + Nested Support)
*/

function buildMountGraph(files) {

  const fileMounts = {};  // childFile -> basePath

  files.forEach(file => {

    try {
      const code = fs.readFileSync(file, "utf8");
      const ast = parseCode(code);

      if (!ast.program || !ast.program.body) return;

      ast.program.body.forEach(node => {

        if (
          node.type === "ExpressionStatement" &&
          node.expression &&
          node.expression.callee &&
          node.expression.callee.property &&
          node.expression.callee.property.name === "use"
        ) {

          const args = node.expression.arguments;

          if (args.length === 2 && args[0].type === "StringLiteral") {

            const basePath = args[0].value;

            /* ============================== */
            /* Handle require('./routes/x')   */
            /* ============================== */

            if (
              args[1].type === "CallExpression" &&
              args[1].callee.name === "require" &&
              args[1].arguments.length === 1
            ) {

              const importPath = args[1].arguments[0].value;

              const resolved = resolveImport(file, importPath);

              if (resolved) {
                fileMounts[resolved] = basePath;
              }
            }

            /* ============================== */
            /* Handle Identifier routers      */
            /* ============================== */

            if (args[1].type === "Identifier") {

              // find where identifier is imported
              const imported = findImportSource(ast, args[1].name, file);

              if (imported) {
                const resolved = resolveImport(file, imported);
                if (resolved) {
                  fileMounts[resolved] = basePath;
                }
              }
            }

          }
        }

      });

    } catch (err) {
      // ignore parse errors
    }

  });

  return fileMounts;
}

/* =============================== */
/* Helpers                         */
/* =============================== */

function resolveImport(currentFile, importPath) {

  if (!importPath.startsWith(".")) return null;

  const baseDir = path.dirname(currentFile);

  const possible = [
    path.resolve(baseDir, importPath + ".ts"),
    path.resolve(baseDir, importPath + ".js"),
    path.resolve(baseDir, importPath, "index.ts"),
    path.resolve(baseDir, importPath, "index.js")
  ];

  for (let p of possible) {
    if (fs.existsSync(p)) return p;
  }

  return null;
}

function findImportSource(ast, identifier, currentFile) {

  for (let node of ast.program.body) {

    if (node.type === "ImportDeclaration") {
      for (let spec of node.specifiers) {
        if (spec.local.name === identifier) {
          return node.source.value;
        }
      }
    }

    if (node.type === "VariableDeclaration") {
      for (let dec of node.declarations) {
        if (
          dec.id.name === identifier &&
          dec.init &&
          dec.init.type === "CallExpression" &&
          dec.init.callee.name === "require"
        ) {
          return dec.init.arguments[0].value;
        }
      }
    }

  }

  return null;
}

module.exports = { buildMountGraph };
