const parser = require("@babel/parser");

function parseCode(code) {
  return parser.parse(code, {
    sourceType: "unambiguous",
    plugins: [
      "jsx",
      "typescript",
      "classProperties",
      "objectRestSpread",
      "optionalChaining"
    ],
    allowReturnOutsideFunction: true,
    errorRecovery: true
  });
}

module.exports = { parseCode };
