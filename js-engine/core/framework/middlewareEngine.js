const parser = require('@babel/parser')
const traverse = require('@babel/traverse').default

// --------------------------------------------------
// Utility: Safe AST Parse
// --------------------------------------------------
function parseHandler(code) {
  if (!code || typeof code !== 'string') return null

  try {
    return parser.parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx']
    })
  } catch {
    return null
  }
}

// --------------------------------------------------
// Auth Heuristic Detection
// --------------------------------------------------
function isAuthIdentifier(name) {
  const lowered = name.toLowerCase()

  return (
    lowered.includes('auth') ||
    lowered.includes('jwt') ||
    lowered.includes('token') ||
    lowered.includes('passport') ||
    lowered.includes('role') ||
    lowered.includes('permission')
  )
}

// --------------------------------------------------
// Main Engine
// --------------------------------------------------
function extractRouteIntelligence(route) {
  const result = {
    usesAuth: false,
    middlewares: [],
    paramAccess: [],
    directUserUsage: false
  }

  if (!route || !route.handlerCode) {
    return result
  }

  const ast = parseHandler(route.handlerCode)

  if (!ast) return result

  traverse(ast, {
    // Detect middleware-style identifiers
    Identifier(path) {
      const name = path.node.name

      if (isAuthIdentifier(name)) {
        result.usesAuth = true

        if (!result.middlewares.includes(name)) {
          result.middlewares.push(name)
        }
      }
    },

    // Detect req.user usage
    MemberExpression(path) {
      const object = path.node.object
      const property = path.node.property

      if (
        object &&
        object.type === 'Identifier' &&
        object.name === 'req' &&
        property &&
        property.type === 'Identifier'
      ) {
        // Detect req.user
        if (property.name === 'user') {
          result.usesAuth = true
          result.directUserUsage = true
        }

        // Detect req.params.*
        if (property.name === 'params') {
          result.paramAccess.push('req.params')
        }

        // Detect req.body.*
        if (property.name === 'body') {
          result.paramAccess.push('req.body')
        }

        // Detect req.query.*
        if (property.name === 'query') {
          result.paramAccess.push('req.query')
        }
      }
    },

    // Detect middleware chaining patterns
    CallExpression(path) {
      const callee = path.node.callee

      if (
        callee.type === 'MemberExpression' &&
        callee.property &&
        isAuthIdentifier(callee.property.name)
      ) {
        result.usesAuth = true

        if (!result.middlewares.includes(callee.property.name)) {
          result.middlewares.push(callee.property.name)
        }
      }
    }
  })

  return result
}

module.exports = { extractRouteIntelligence }
