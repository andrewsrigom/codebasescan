export async function cachedCatalog(tenantId: string) {
  'use cache';
  return db.product.findMany({ where: { tenantId, published: true } });
}
