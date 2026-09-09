import { database } from '../../../../lib/database';
import { requireSession } from '../../../../lib/auth';

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  await requireSession(request);
  const { id } = await context.params;
  const project = await database.project.findUnique({ where: { id } });
  return Response.json(project);
}
