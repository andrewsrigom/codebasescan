export async function PATCH(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  return prisma.project.update({ where: { id }, data: { archived: true } });
}
