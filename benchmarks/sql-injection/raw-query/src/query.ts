export async function search(query: string) {
  return database.$queryRawUnsafe(query);
}
