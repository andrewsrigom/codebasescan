import { auth } from './src/lib/auth';

export async function proxy() {
  await auth();
}

export const config = { matcher: ['/api/:path*'] };
