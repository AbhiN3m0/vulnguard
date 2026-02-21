const cweDB = require("./cweDatabase.json");

function enrichWithIntelligence(finding) {
  const cweId = finding.cwe;

  if (!cweId || !cweDB[cweId]) {
    return finding;
  }

  const weakness = cweDB[cweId];

  /* ================= Impact Calculation ================= */

  const impactScore =
    (weakness.impact.confidentiality +
      weakness.impact.integrity +
      weakness.impact.availability) / 3;

  /* ================= Exploitability ================= */

  const exploitability = weakness.exploitability;

  /* ================= Risk Score ================= */

  let contextualBoost = 0;

  if (finding.routeMethod === "delete") contextualBoost += 0.2;
  if (finding.routePath && finding.routePath.includes("admin"))
    contextualBoost += 0.3;
  if (finding.severity === "Critical") contextualBoost += 0.3;

  const riskScore =
    (impactScore * 5 + exploitability * 5) + contextualBoost * 10;

  /* ================= Dynamic Confidence ================= */

  let confidence = weakness.base_confidence;

  if (finding.confidence) {
    confidence = (confidence + finding.confidence) / 2;
  }

  if (finding.routeMethod === "post" || finding.routeMethod === "delete") {
    confidence += 0.05;
  }

  if (confidence > 1) confidence = 1;

  /* ================= Replace CVSS ================= */

  const dynamicCVSS = (impactScore * 6 + exploitability * 4).toFixed(1);

  return {
    ...finding,
    intelligence_category: weakness.category,
    risk_score: parseFloat(riskScore.toFixed(2)),
    cvss_score: parseFloat(dynamicCVSS),
    confidence: parseFloat(confidence.toFixed(2))
  };
}

module.exports = { enrichWithIntelligence };
