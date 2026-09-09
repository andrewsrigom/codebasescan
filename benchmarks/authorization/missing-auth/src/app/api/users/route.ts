import { database } from '../../../../database';
export async function DELETE() {
  await database.user.delete({ where: { id: 'fixture' } });
  return new Response(null, { status: 204 });
}
