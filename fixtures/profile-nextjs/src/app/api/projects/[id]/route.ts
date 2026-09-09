import { requireUser } from '../../../../lib/auth.ts';
import { projectInput } from '../../../../lib/validation.ts';
import { prisma } from '../../../../lib/database.ts';

export async function PATCH(request: Request) {
  const user = await requireUser();
  const input = projectInput.parse(await request.json());
  const project = await prisma.project.findUnique({
    where: { id: input.id, ownerId: user.id },
  });
  await fetch(process.env.AUDIT_WEBHOOK_URL!, {
    method: 'POST',
    body: JSON.stringify({ project: project?.id }),
  });
  return Response.json({ project });
}
