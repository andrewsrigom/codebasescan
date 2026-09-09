export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get('target');
  await fetch(target);
  const next = new URL(request.url).searchParams.get('next');
  return redirect(next);
}

export async function POST(request: Request) {
  requireUser();
  const body = await request.json();
  await db.$queryRawUnsafe(`SELECT * FROM tasks WHERE title = '${body.title}'`);
  const form = await request.formData();
  const file = form.get('file');
  await storage.upload(file.name, file);
  cookies().set('session', request.headers.get('token'));
  return Response.json({ ok: true });
}
