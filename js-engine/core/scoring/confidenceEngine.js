function calculateScore(finding) {

  let severity = "Medium";
  let confidence = 0.7;

  /* ================= Injection ================= */

  if (finding.type === "Command Injection") {
    severity = "Critical";
    confidence = 0.95;
  }

  if (finding.type === "SQL Injection") {
    severity = "Critical";
    confidence = 0.9;
  }

  if (finding.type === "Cross-Site Scripting (XSS)") {
    severity = "High";
    confidence = 0.8;
  }

  /* ================= Access Control ================= */

  if (finding.type === "Missing Authorization Check") {

    const path = (finding.routePath || "").toLowerCase();
    const method = (finding.routeMethod || "").toLowerCase();

    // Critical routes
    if (
      path.includes("admin") ||
      path.includes("root") ||
      path.includes("config") ||
      path.includes("system")
    ) {
      severity = "Critical";
      confidence = 0.9;
    }

    // High-risk operations
    else if (
      method === "post" ||
      method === "put" ||
      method === "delete" ||
      path.includes("delete") ||
      path.includes("update") ||
      path.includes("create") ||
      path.includes("transfer")
    ) {
      severity = "High";
      confidence = 0.8;
    }

    // Medium sensitive routes
    else if (
      path.includes("profile") ||
      path.includes("account") ||
      path.includes("data")
    ) {
      severity = "Medium";
      confidence = 0.7;
    }

    // Low-risk public endpoints
    else if (
      path.includes("login") ||
      path.includes("signup") ||
      path.includes("public") ||
      path.includes("health")
    ) {
      severity = "Low";
      confidence = 0.6;
    }

    // Static GET routes
    else if (method === "get") {
      severity = "Info";
      confidence = 0.5;
    }
  }

  return {
    ...finding,
    severity,
    confidence
  };
}

module.exports = { calculateScore };
