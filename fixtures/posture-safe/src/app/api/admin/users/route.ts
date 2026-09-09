import { cookies } from 'next/headers';
import { auth, authorize } from '../../../../../lib/auth';
import { database } from '../../../../../lib/database';

export async function DELETE(request: Request) {
  const session = await auth();
  authorize(session, 'users:delete');
  const id = new URL(request.url).searchParams.get('id');
  cookies().set('session', 'fixture-session', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  });
  const user = await database.user.findFirst({ where: { id, tenantId: session.tenantId } });
  if (!user) return new Response(null, { status: 404 });
  await database.user.delete({ where: { id: user.id, tenantId: session.tenantId } });
  return Response.json(user);
}
