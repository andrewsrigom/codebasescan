const trustedOrigins = new Set(['https://app.example.test']);

export function POST(request: Request) {
  const origin = request.headers.get('origin') ?? '';
  if (!trustedOrigins.has(origin)) return new Response(null, { status: 403 });
  return Response.json({ ok: true }, { headers: { 'Access-Control-Allow-Origin': origin } });
}
