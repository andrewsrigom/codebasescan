export async function recordCallback(request: Request) {
  const body = await request.json();
  logger.info({ email: body.email, token: body.token }, 'callback');
  const callback = new URL('https://example.test/callback');
  callback.searchParams.set('token', body.token);
  return callback;
}
