export async function DELETE(request: Request) {
  const id = new URL(request.url).searchParams.get('id');
  return db.user.delete({ where: { id } });
}
