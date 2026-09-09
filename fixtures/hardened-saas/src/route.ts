export async function findProject(database: Database, session: Session, id: string) {
  return database.project.findFirst({
    where: { id, tenantId: session.tenantId },
  });
}

export async function search(database: Database, name: string) {
  return database.project.findMany({ where: { name } });
}
