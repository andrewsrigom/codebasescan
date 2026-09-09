'use server';

import { auth, authorize } from '../../lib/auth';
import { database } from '../../lib/database';

export async function removeUser(id: string) {
  const session = await auth();
  authorize(session, 'users:delete');
  return database.user.delete({ where: { id, tenantId: session.tenantId } });
}
