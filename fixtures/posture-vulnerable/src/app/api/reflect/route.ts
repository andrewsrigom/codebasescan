export function POST(request: Request) {
  return Response.json(
    { ok: true },
    { headers: { 'Access-Control-Allow-Origin': request.headers.get('origin') ?? '' } },
  );
}
