export async function middleware() {
  return requireUser();
}

export const config = { matcher: ['/api/accounts/:path*'] };
