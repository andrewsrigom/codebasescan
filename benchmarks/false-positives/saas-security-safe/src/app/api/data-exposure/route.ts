export async function POST(request: Request) {
  const body = await request.json();
  logger.info({ emailHash: hash(body.email) }, 'callback');
  return fetch('https://example.test/callback', {
    headers: { authorization: `Bearer ${body.token}` },
  });
}
