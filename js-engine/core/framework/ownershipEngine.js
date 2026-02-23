const parser = require('@babel/parser')
const traverse = require('@babel/traverse').default

function detectOwnershipValidation(route) {
  if (!route.handlerCode) {
    return { usesReqUser: false, ownershipValidated: false }
  }

  let ast
  try {
    ast = parser.parse(route.handlerCode, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx']
    })
  } catch {
    return { usesReqUser: false, ownershipValidated: false }
  }

  let usesReqUser = false
  let ownershipValidated = false

  traverse(ast, {
    MemberExpression(path) {
      const node = path.node

      // Detect req.user
      if (
        node.object &&
        node.object.type === 'MemberExpression' &&
        node.object.object?.name === 'req' &&
        node.object.property?.name === 'user'
      ) {
        usesReqUser = true
      }
    },

    BinaryExpression(path) {
      const { left, right } = path.node

      const containsReqUser =
        JSON.stringify(left).includes('req') ||
        JSON.stringify(right).includes('req')

      const containsUserId =
        JSON.stringify(left).includes('userId') ||
        JSON.stringify(right).includes('userId')

      if (containsReqUser && containsUserId) {
        ownershipValidated = true
      }
    },

    ObjectProperty(path) {
      const key = path.node.key
      const value = path.node.value

      if (
        key.name === 'userId' &&
        JSON.stringify(value).includes('req')
      ) {
        ownershipValidated = true
      }
    }
  })

  return {
    usesReqUser,
    ownershipValidated
  }
}

module.exports = {
  detectOwnershipValidation
}
