
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const { parseCode } = require("./core/parser/astParser");
const { loadRules } = require("./ruleLoader");
const { calculateScore } = require("./core/scoring/confidenceEngine");
const { enrichWithTaxonomy } = require("./core/enrichment/taxonomyMapper");
const { enrichWithIntelligence } = require("./core/intelligence/intelligenceEngine");
const { generateSarif } = require("./core/reporters/sarifExporter");

/* ================= CONFIG ================= */

const MAX_AI_FINDINGS = 10;

/* ================= FILE COLLECTION ================= */

function getAllSourceFiles(dirPath, arrayOfFiles = []) {
  const files = fs.readdirSync(dirPath);

  files.forEach(file => {
    const fullPath = path.join(dirPath, file);

    if (fs.statSync(fullPath).isDirectory()) {
      if (
        ![
          "node_modules",
          "dist",
          "build",
          "frontend",
          "uploads",
          "data",
          "test"
        ].includes(file)
      ) {
        getAllSourceFiles(fullPath, arrayOfFiles);
      }
    } else if (
      (file.endsWith(".js") || file.endsWith(".ts")) &&
      !file.endsWith(".min.js") &&
      !fullPath.includes("node_modules") &&
      !fullPath.includes("dist") &&
      !fullPath.includes("frontend")
    ) {
      arrayOfFiles.push(fullPath);
    }
  });

  return arrayOfFiles;
}

/* ================= CLI ================= */

const args = process.argv.slice(2);

if (args.length === 0) {
  console.log(
    "Usage: npm run scan -- <file-or-directory> --mode <practical|research|ai|sarif>"
  );
  process.exit(1);
}

const targetPath = args[0];

let mode = "practical";
if (args.includes("--mode")) {
  const modeIndex = args.indexOf("--mode");
  mode = args[modeIndex + 1] || "practical";
}

console.log(`🔎 VulnGuard running in ${mode.toUpperCase()} mode\n`);

if (!fs.existsSync(targetPath)) {
  console.log("❌ Target path does not exist.");
  process.exit(1);
}

/* ================= DETERMINE FILES ================= */

let filesToScan = [];

if (fs.statSync(targetPath).isDirectory()) {
  filesToScan = getAllSourceFiles(targetPath);
} else {
  filesToScan = [targetPath];
}

/* ================= LOAD RULES ================= */

const rules = loadRules();

/* ================= SCAN ================= */

let allFindings = [];

filesToScan.forEach(file => {
  try {
    const code = fs.readFileSync(file, "utf8");
    const ast = parseCode(code);

    rules.forEach(rule => {
      const results = rule.analyze(ast, file, mode);

      results.forEach(r => {
        let enriched = calculateScore(r);
        enriched = enrichWithTaxonomy(enriched);
        enriched = enrichWithIntelligence(enriched);
        allFindings.push(enriched);
      });
    });

  } catch (err) {
    console.log(`⚠️ Skipping ${file} (parse error)`);
  }
});

/* ================= NO FINDINGS ================= */

if (allFindings.length === 0) {
  console.log("✅ No vulnerabilities found.");
  process.exit(0);
}

/* ================= OUTPUT MODES ================= */

if (mode === "ai") {

  let aiFindings = allFindings.filter(
    f => f.severity === "High" || f.severity === "Critical"
  );

  if (aiFindings.length === 0) {
    console.log("ℹ️ No High/Critical findings for AI analysis.");
  } else {

    if (aiFindings.length > MAX_AI_FINDINGS) {
      console.log(`⚠️ Limiting AI to top ${MAX_AI_FINDINGS} findings\n`);
      aiFindings = aiFindings.slice(0, MAX_AI_FINDINGS);
    }

    console.log(`Sending ${aiFindings.length} findings to AI...\n`);

    const pythonRisk = spawnSync(
      "venv/bin/python",
      ["ai-engine/exploit_scorer.py"],
      {
        input: JSON.stringify(aiFindings),
        encoding: "utf-8"
      }
    );

    let riskEnhanced = [];
    try {
      riskEnhanced = JSON.parse(pythonRisk.stdout);
    } catch {
      riskEnhanced = aiFindings;
    }

    const pythonLLM = spawnSync(
      "venv/bin/python",
      ["ai-engine/llm_reasoner.py"],
      {
        input: JSON.stringify(riskEnhanced),
        encoding: "utf-8"
      }
    );

    let finalEnhanced = [];
    try {
      finalEnhanced = JSON.parse(pythonLLM.stdout);
    } catch {
      finalEnhanced = riskEnhanced;
    }

    console.log("🤖 AI + LLM Enhanced Findings:\n");
    console.log(JSON.stringify(finalEnhanced, null, 2));
  }

} else if (mode === "sarif") {

  const sarif = generateSarif(allFindings);

  fs.writeFileSync(
    "vulnguard-report.sarif",
    JSON.stringify(sarif, null, 2)
  );

  console.log("📄 SARIF report generated: vulnguard-report.sarif");

} else {

  console.log("🚨 Vulnerabilities Found:\n");
  console.log(JSON.stringify(allFindings, null, 2));
}

/* ================= SUMMARY (BOTTOM) ================= */

console.log("\n===============================");
console.log(`Total Findings: ${allFindings.length}`);

const severitySummary = {
  Critical: 0,
  High: 0,
  Medium: 0,
  Low: 0,
  Info: 0
};

allFindings.forEach(f => {
  if (severitySummary[f.severity] !== undefined) {
    severitySummary[f.severity]++;
  }
});

console.log("Severity Breakdown:");
console.log(severitySummary);
console.log("===============================\n");

/* ================= CI AUTO-FAIL ================= */

const hasCritical = allFindings.some(
  f => f.severity === "Critical"
);

if (hasCritical && mode !== "practical") {
  console.log("❌ Build failed due to Critical vulnerabilities.");
  process.exit(1);
}

process.exit(0);
