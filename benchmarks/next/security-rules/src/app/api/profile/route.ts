export async function GET() {
  await requireUser();
  const response = Response.json(await db.profile.findMany());
  response.headers.set('Cache-Control', 'public, s-maxage=300');
  return response;
}

export async function POST(request: Request) {
  await requireUser();
  const body = await request.json();
  return Response.json({ accessToken: await db.profile.create({ data: body }) });
}
