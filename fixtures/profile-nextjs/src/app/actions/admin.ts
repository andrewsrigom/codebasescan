'use server';

import { requireRole } from '../../lib/auth.ts';
import { prisma } from '../../lib/database.ts';

export async function deleteProject(id: string) {
  await requireRole('admin');
  return prisma.project.delete({ where: { id } });
}
