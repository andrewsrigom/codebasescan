import { NextResponse, type NextRequest } from 'next/server';
import { localRequestError } from './security/local-http.ts';
export function proxy(request: NextRequest) {
  const error = localRequestError(
    request,
    process.env.TRACEWARD_PORT ?? '3000',
    process.env.TRACEWARD_INTERNAL_HOST,
  );
  if (error) return new NextResponse(error, { status: 403 });
  return NextResponse.next();
}
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
