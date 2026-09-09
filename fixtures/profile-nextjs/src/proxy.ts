import { requireUser } from './lib/auth.ts';

export async function proxy() {
  await requireUser();
}

export const config = { matcher: ['/api/:path*'] };
