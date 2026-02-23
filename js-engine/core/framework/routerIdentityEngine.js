const fs = require('fs')
const parser = require('@babel/parser')
const traverse = require('@babel/traverse').default

const HTTP_METHODS = [
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'options',
  'head'
]

// --------------------------------------------------
// Parse File
// --------------------------------------------------

function parseFile(filePath) {
  try {
    const code = fs.readFileSync(filePath, 'utf8')
    return parser.parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx']
    })
  } catch {
    return null
  }
}

// --------------------------------------------------
// Router Identity Engine
// --------------------------------------------------

function buildRouterIdentity(filePath) {
  const ast = parseFile(filePath)
  if (!ast) return []

  const routes = []

  const expressImports = new Set()
  const appInstances = new Set()
  const routerInstances = new Set()
  const aliasMap = new Map() // alias -> original
  const mountPrefixes = new Map() // routerName -> prefix

  // --------------------------------------------------
  // First Pass – Detect Express + Router Instances
  // --------------------------------------------------

  traverse(ast, {
    ImportDeclaration(path) {
      if (path.node.source.value === 'express') {
        path.node.specifiers.forEach(spec => {
          if (spec.local?.name) {
            expressImports.add(spec.local.name)
          }
        })
      }
    },

    VariableDeclarator(path) {
      const { node } = path
      if (!node.init) return

      // const app = express()
      if (
        node.init.type === 'CallExpression' &&
        node.init.callee.type === 'Identifier' &&
        expressImports.has(node.init.callee.name)
      ) {
        appInstances.add(node.id.name)
      }

      // const router = express.Router()
      if (
        node.init.type === 'CallExpression' &&
        node.init.callee.type === 'MemberExpression' &&
        node.init.callee.object.type === 'Identifier' &&
        expressImports.has(node.init.callee.object.name) &&
        node.init.callee.property.name === 'Router'
      ) {
        routerInstances.add(node.id.name)
      }

      // Alias tracking
      if (
        node.init.type === 'Identifier' &&
        (routerInstances.has(node.init.name) ||
          appInstances.has(node.init.name))
      ) {
        aliasMap.set(node.id.name, node.init.name)
      }
    }
  })

  // --------------------------------------------------
  // Resolve Alias Helper
  // --------------------------------------------------

  function resolveAlias(name) {
    let current = name
    while (aliasMap.has(current)) {
      current = aliasMap.get(current)
    }
    return current
  }

  // --------------------------------------------------
  // Second Pass – Detect Routes + Mounts
  // --------------------------------------------------

  traverse(ast, {
    CallExpression(path) {
      const { node } = path

      if (node.callee.type !== 'MemberExpression') return

      const object = node.callee.object
      const property = node.callee.property

      if (!object || object.type !== 'Identifier') return
      if (!property || property.type !== 'Identifier') return

      const objectName = resolveAlias(object.name)
      const method = property.name

      // --------------------------------------------------
      // Detect app.use('/prefix', router)
      // --------------------------------------------------

      if (
        method === 'use' &&
        appInstances.has(objectName) &&
        node.arguments.length >= 2
      ) {
        const [prefixArg, routerArg] = node.arguments

        if (
          prefixArg.type === 'StringLiteral' &&
          routerArg.type === 'Identifier'
        ) {
          mountPrefixes.set(routerArg.name, prefixArg.value)
        }
      }

      // --------------------------------------------------
      // Detect HTTP routes
      // --------------------------------------------------

      if (!HTTP_METHODS.includes(method)) return

      if (
        !appInstances.has(objectName) &&
        !routerInstances.has(objectName)
      ) {
        return
      }

      if (!node.arguments.length) return

      const routeArg = node.arguments[0]

      if (routeArg.type !== 'StringLiteral') return

      let routePath = routeArg.value

      // Apply mount prefix if router
      if (routerInstances.has(objectName)) {
        const prefix = mountPrefixes.get(objectName)
        if (prefix) {
          routePath = prefix + routePath
        }
      }

      routes.push({
        file: filePath,
        line: node.loc?.start.line || 0,
        routeMethod: method,
        routePath,
        middlewares: []
      })
    }
  })

  return routes
}

module.exports = { buildRouterIdentity }
