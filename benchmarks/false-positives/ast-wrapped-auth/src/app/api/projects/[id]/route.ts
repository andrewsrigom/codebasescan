import { requireProjectAccess } from '../../../../lib/access.ts';

export async function PATCH(_request: Request, context: { params: Promise<{ id: string }> }) {
  const user = await requireProjectAccess();
  const { id } = await context.params;
  return prisma.project.update({ where: { id, ownerId: user.id }, data: { archived: true } });
}
