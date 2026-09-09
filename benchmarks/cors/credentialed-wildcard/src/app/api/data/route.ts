export async function DELETE() {
  await auth();
  authorize('data:delete');
  return Response.json(
    { ok: true },
    {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
      },
    },
  );
}
