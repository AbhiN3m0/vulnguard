const InjectionRule = require("./rules/injectionRule");
const AccessControlRule = require("./rules/accessControlRule");
const XSSRule = require("./rules/xssRule");

function loadRules() {
  return [
    new InjectionRule(),
    new AccessControlRule(),
    new XSSRule()
  ];
}

module.exports = { loadRules };
