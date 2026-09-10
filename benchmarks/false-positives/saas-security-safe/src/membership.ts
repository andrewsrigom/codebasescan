export async function updateMembership(request: Request) {
  const session = await requireSession();
  const body = await request.json();
  return database.member.update({
    where: { tenantId: session.user.tenantId },
    data: { displayName: body.displayName },
  });
}
