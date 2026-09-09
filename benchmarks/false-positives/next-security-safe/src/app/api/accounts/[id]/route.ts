export async function GET(_request: Request, { params }) {
  const user = await requireUser();
  return Response.json(await db.account.findFirst({ where: { id: params.id, ownerId: user.id } }));
}

export async function POST(request: Request) {
  const user = await requireUser();
  const body = accountSchema.parse(await request.json());
  const account = await db.account.create({ data: { ...body, ownerId: user.id } });
  return Response.json({ id: account.id });
}
