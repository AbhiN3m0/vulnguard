const parser = require('@babel/parser')
const traverse = require('@babel/traverse').default

// --------------------------------------------
// Safe AST Parse
// --------------------------------------------
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

// --------------------------------------------
// Known DB operations
// --------------------------------------------
const DB_OPERATIONS = [
  'findOne',
  'findByPk',
  'findAll',
  'create',
  'update',
  'destroy',
  'delete',
  'remove',
  'save'
]

// --------------------------------------------
// Main Engine
// --------------------------------------------
function extractDbAccess(route) {
  const results = []

  if (!route || !route.handlerCode) {
    return results
  }

  const ast = parseHandler(route.handlerCode)
  if (!ast) return results

  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee

      if (
        callee.type === 'MemberExpression' &&
        callee.property &&
        DB_OPERATIONS.includes(callee.property.name)
      ) {
        const modelNode = callee.object
        const operation = callee.property.name

        let modelName = null

        if (modelNode.type === 'Identifier') {
          modelName = modelNode.name
        }

        let paramSource = null
        let paramName = null

        path.traverse({
          MemberExpression(innerPath) {
            const obj = innerPath.node.object
            const prop = innerPath.node.property

            if (
              obj &&
              obj.type === 'Identifier' &&
              obj.name === 'req' &&
              prop &&
              prop.type === 'Identifier'
            ) {
              paramSource = `req.${prop.name}`
            }
          }
        })

        results.push({
          model: modelName,
          operation,
          paramName,
          paramSource
        })
      }
    }
  })

  return results
}

module.exports = { extractDbAccess }
