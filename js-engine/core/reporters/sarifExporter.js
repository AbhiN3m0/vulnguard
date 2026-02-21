function generateSarif(findings) {
  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "VulnGuard",
            informationUri: "https://vulnguard.local",
            rules: []
          }
        },
        results: []
      }
    ]
  };

  const ruleSet = new Map();

  findings.forEach((finding, index) => {
    const ruleId = finding.type.replace(/\s+/g, "_");

    if (!ruleSet.has(ruleId)) {
      ruleSet.set(ruleId, {
        id: ruleId,
        name: finding.type,
        shortDescription: {
          text: finding.type
        },
        fullDescription: {
          text: `Detected ${finding.type}`
        },
        defaultConfiguration: {
          level:
            finding.severity === "Critical"
              ? "error"
              : finding.severity === "High"
              ? "warning"
              : "note"
        }
      });
    }

    sarif.runs[0].results.push({
      ruleId,
      level:
        finding.severity === "Critical"
          ? "error"
          : finding.severity === "High"
          ? "warning"
          : "note",
      message: {
        text: `${finding.type} detected (Confidence: ${finding.confidence})`
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.file
            },
            region: {
              startLine: finding.line
            }
          }
        }
      ]
    });
  });

  sarif.runs[0].tool.driver.rules = Array.from(ruleSet.values());

  return sarif;
}

module.exports = { generateSarif };
