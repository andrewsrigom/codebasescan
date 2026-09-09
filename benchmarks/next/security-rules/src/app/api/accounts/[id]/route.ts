export async function GET(_request: Request, { params }) {
  return Response.json(await db.account.findUnique({ where: { id: params.id } }));
}
