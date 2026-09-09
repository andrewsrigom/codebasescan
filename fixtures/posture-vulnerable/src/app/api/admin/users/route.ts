import { cookies } from 'next/headers';
import { database } from '../../../../lib/database';

export async function DELETE(request: Request) {
  const id = new URL(request.url).searchParams.get('id');
  cookies().set('session', 'fixture-session', { sameSite: 'none' });
  const user = await database.user.findUnique({ where: { id } });
  await database.user.delete({ where: { id: user.id } });
  return Response.json(user, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': 'true',
    },
  });
}
