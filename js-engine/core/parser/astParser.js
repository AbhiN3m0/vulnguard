const parser = require("@babel/parser");

function parseCode(code) {

  return parser.parse(code, {
    sourceType: "unambiguous",
    allowReturnOutsideFunction: true,
    errorRecovery: true,
    plugins: [
      "typescript",
      "jsx",
      "classProperties",
      "classPrivateProperties",
      "classPrivateMethods",
      "decorators-legacy",
      "dynamicImport",
      "optionalChaining",
      "nullishCoalescingOperator",
      "objectRestSpread",
      "numericSeparator",
      "topLevelAwait"
    ]
  });

}

module.exports = { parseCode };
