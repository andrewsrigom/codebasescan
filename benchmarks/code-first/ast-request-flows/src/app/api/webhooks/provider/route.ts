export async function POST(request: Request) {
  const body = await request.json();
  verifySignature(body);
  return db.event.create({ data: body });
}
