export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get('target');
  assertSafeUrl(target);
  await fetch(target);
  return redirect('/dashboard');
}

export async function POST(request: Request) {
  requireUser();
  const body = await request.json();
  await db.$queryRaw`SELECT * FROM tasks WHERE title = ${body.title}`;
  const form = await request.formData();
  const file = form.get('file');
  validateUpload(file);
  await storage.upload('generated-name', file);
  const options = { secure: true, httpOnly: true, sameSite: 'lax' };
  cookies().set('session', 'opaque', options);
  return Response.json({ ok: true });
}
