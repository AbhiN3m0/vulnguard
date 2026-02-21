function calculateCVSS(finding) {
  let baseScore = 5.0;

  if (finding.severity === "Critical") {
    baseScore = 9.8;
  }

  if (finding.type.includes("Inter-procedural")) {
    baseScore += 0.1;
  }

  return {
    ...finding,
    cvss_score: Number(baseScore.toFixed(1))
  };
}

module.exports = { calculateCVSS };
