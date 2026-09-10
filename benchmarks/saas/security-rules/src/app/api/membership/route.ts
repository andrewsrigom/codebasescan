export async function PATCH(request: Request) {
  const body = await request.json();
  return database.member.update({
    where: { tenantId: body.tenantId },
    data: { role: body.role },
  });
}
