import { cookies } from 'next/headers';

export async function cachedDashboard() {
  'use cache';
  const session = cookies().get('session');
  return db.dashboard.findMany({ where: { session } });
}
