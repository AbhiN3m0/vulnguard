const fs = require('fs')
const path = require('path')
const parser = require('@babel/parser')
const traverse = require('@babel/traverse').default

// Supported file extensions
const EXTENSIONS = ['.ts', '.js']

// --------------------------------------------------
// Utility: Safe File Read
// --------------------------------------------------
function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8')
  } catch {
    return null
  }
}

// --------------------------------------------------
// Utility: Check If File Exists With Extensions
// --------------------------------------------------
function resolveWithExtensions(basePath) {
  for (const ext of EXTENSIONS) {
    const full = basePath.endsWith(ext) ? basePath : basePath + ext
    if (fs.existsSync(full)) return full
  }

  // Handle directory index files
  if (fs.existsSync(basePath) && fs.lstatSync(basePath).isDirectory()) {
    for (const ext of EXTENSIONS) {
      const idx = path.join(basePath, 'index' + ext)
      if (fs.existsSync(idx)) return idx
    }
  }

  return null
}

// --------------------------------------------------
// Step 1 — Detect Entrypoint
// --------------------------------------------------
function detectEntrypoint(rootDir, explicitEntry = null) {
  if (explicitEntry) {
    const full = path.resolve(rootDir, explicitEntry)
    if (fs.existsSync(full)) return full
    throw new Error(`Entrypoint not found: ${explicitEntry}`)
  }

  const candidates = ['server.ts', 'app.ts', 'index.ts', 'main.ts']

  for (const file of candidates) {
    const full = path.join(rootDir, file)
    if (fs.existsSync(full)) {
      return full
    }
  }

  throw new Error('No entrypoint detected (server.ts/app.ts/index.ts)')
}

// --------------------------------------------------
// Step 2 — Extract Imports From AST
// --------------------------------------------------
function extractImports(filePath) {
  const code = readFileSafe(filePath)
  if (!code) return []

  let ast
  try {
    ast = parser.parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx']
    })
  } catch {
    return []
  }

  const imports = []

  traverse(ast, {
    ImportDeclaration(pathNode) {
      const source = pathNode.node.source.value
      imports.push(source)
    },
    CallExpression(pathNode) {
      const callee = pathNode.node.callee
      if (
        callee.type === 'Identifier' &&
        callee.name === 'require' &&
        pathNode.node.arguments.length === 1 &&
        pathNode.node.arguments[0].type === 'StringLiteral'
      ) {
        imports.push(pathNode.node.arguments[0].value)
      }
    }
  })

  return imports
}

// --------------------------------------------------
// Step 3 — Resolve Local Module Path
// --------------------------------------------------
function resolveImport(currentFile, importPath, rootDir) {
  // Ignore external modules
  if (!importPath.startsWith('.') && !importPath.startsWith('/')) {
    return null
  }

  let resolved

  if (importPath.startsWith('/')) {
    resolved = path.join(rootDir, importPath)
  } else {
    resolved = path.resolve(path.dirname(currentFile), importPath)
  }

  return resolveWithExtensions(resolved)
}

// --------------------------------------------------
// Step 4 — Build Dependency Graph
// --------------------------------------------------
function buildDependencyGraph(entryFile, rootDir) {
  const graph = new Map()
  const visited = new Set()

  function walk(file) {
    if (!file || visited.has(file)) return
    visited.add(file)

    const imports = extractImports(file)
    const resolvedImports = []

    for (const imp of imports) {
      const resolved = resolveImport(file, imp, rootDir)
      if (resolved) {
        resolvedImports.push(resolved)
        walk(resolved)
      }
    }

    graph.set(file, resolvedImports)
  }

  walk(entryFile)

  return {
    graph,
    reachableFiles: Array.from(visited)
  }
}

// --------------------------------------------------
// Public API
// --------------------------------------------------
function buildReachability(rootDir, options = {}) {
  const entry = detectEntrypoint(rootDir, options.entry)

  const { graph, reachableFiles } = buildDependencyGraph(entry, rootDir)

  return {
    entrypoint: entry,
    graph,
    reachableFiles
  }
}

module.exports = {
  buildReachability
}
