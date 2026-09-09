'use server';

import { database } from '../../lib/database';

export async function removeUser(id: string) {
  return database.user.delete({ where: { id } });
}
