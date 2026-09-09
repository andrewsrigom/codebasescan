export async function POST(request: Request) {
  const raw = await request.text();
  verifySignature(raw, request.headers.get('signature'));
  const body = JSON.parse(raw);
  return db.event.create({ data: body });
}
