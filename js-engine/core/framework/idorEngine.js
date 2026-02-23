function detectIDOR({ route, middlewareInfo, dbAccess, ownershipInfo }) {
  const hasRouteParam =
    route.fullPath && route.fullPath.includes(':')

  const dbUsesParam =
    dbAccess &&
    dbAccess.some(d =>
      JSON.stringify(d).includes('req.params')
    )

  const isIDOR =
    hasRouteParam &&
    dbUsesParam &&
    !middlewareInfo.usesAuth &&
    !ownershipInfo.ownershipValidated

  return { isIDOR }
}

module.exports = {
  detectIDOR
}
