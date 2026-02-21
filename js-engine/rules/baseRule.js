class BaseRule {
  constructor(name) {
    this.name = name;
  }

  analyze(ast, filePath, mode) {
    throw new Error("analyze() must be implemented by rule.");
  }
}

module.exports = BaseRule;
