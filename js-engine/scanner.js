const fs = require('fs')
const path = require('path')

const { buildReachability } = require('./core/framework/reachabilityEngine')
const { buildRouterIdentity } = require('./core/framework/routerIdentityEngine')
const { extractRouteIntelligence } = require('./core/framework/middlewareEngine')
const { extractDbAccess } = require('./core/framework/dbAccessEngine')
const { detectOwnershipValidation } = require('./core/framework/ownershipEngine')
const { detectIDOR } = require('./core/framework/idorEngine')

// --------------------------------------------------
// CLI Handling
// --------------------------------------------------

const args = process.argv.slice(2)

if (!args.length) {
  console.error('Usage: node scanner.js <targetDir> --mode research')
  process.exit(1)
}

const targetDir = args[0]
const mode = args.includes('--mode') ? args[args.indexOf('--mode') + 1] : 'research'

console.log(`🔎 VulnGuard running in ${mode.toUpperCase()} mode\n`)

const absoluteTarget = path.resolve(targetDir)

if (!fs.existsSync(absoluteTarget)) {
  console.error('Target directory does not exist')
  process.exit(1)
}

// --------------------------------------------------
// 1️⃣ Reachability Phase
// --------------------------------------------------

const reachability = buildReachability(absoluteTarget)

console.log(`📌 Entrypoint: ${reachability.entrypoint}`)
console.log(`📡 Reachable Files Count: ${reachability.reachableFiles.length}\n`)

// --------------------------------------------------
// 2️⃣ Route Discovery Phase
// --------------------------------------------------

let routes = []

for (const file of reachability.reachableFiles) {
  const fileRoutes = buildRouterIdentity(file)

  if (Array.isArray(fileRoutes) && fileRoutes.length > 0) {
    routes.push(...fileRoutes)
  }
}

console.log(`🛣️  Total Routes Discovered: ${routes.length}\n`)

// --------------------------------------------------
// 3️⃣ Correlated Analysis Phase
// --------------------------------------------------

const findings = []

for (const route of routes) {
  const middlewareInfo = extractRouteIntelligence(route)
  const dbAccess = extractDbAccess(route)
  const ownershipInfo = detectOwnershipValidation(route)

  const idorInfo = detectIDOR({
    route,
    middlewareInfo,
    dbAccess,
    ownershipInfo
  })

  // --------------------------------------------------
  // Missing Authorization Check
  // --------------------------------------------------

  const hasAuth =
    middlewareInfo?.usesAuth ||
    ownershipInfo?.hasOwnershipValidation

  if (!hasAuth) {
    findings.push({
      file: route.file,
      type: 'Missing Authorization Check',
      line: route.line,
      routePath: route.routePath,
      routeMethod: route.routeMethod,
      middlewares: route.middlewares || [],
      usesAuth: false,
      dbAccess,
      cwe: 'CWE-285',
      owasp: 'A01:2021 - Broken Access Control',
      severity: route.routeMethod === 'get' ? 'Info' : 'High',
      confidence: route.routeMethod === 'get' ? 0.5 : 0.8,
      cvss_score: 5
    })
  }

  // --------------------------------------------------
  // IDOR Detection
  // --------------------------------------------------

  if (idorInfo?.isIDOR) {
    findings.push({
      file: route.file,
      type: 'Insecure Direct Object Reference (IDOR)',
      line: route.line,
      routePath: route.routePath,
      routeMethod: route.routeMethod,
      dbAccess,
      cwe: 'CWE-639',
      owasp: 'A01:2021 - Broken Access Control',
      severity: 'High',
      confidence: 0.9,
      cvss_score: 7
    })
  }
}

// --------------------------------------------------
// 4️⃣ Output
// --------------------------------------------------

console.log('🚨 Vulnerabilities Found:\n')
console.log(JSON.stringify(findings, null, 2))

// --------------------------------------------------
// 5️⃣ Summary
// --------------------------------------------------

const severityBreakdown = findings.reduce((acc, f) => {
  acc[f.severity] = (acc[f.severity] || 0) + 1
  return acc
}, {})

console.log('\n===============================')
console.log(`Total Findings: ${findings.length}`)
console.log('Severity Breakdown:')
console.log(severityBreakdown)
console.log('===============================\n')
