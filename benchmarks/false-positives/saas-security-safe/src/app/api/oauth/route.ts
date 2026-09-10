const REDIRECT_URIS = { application: 'https://app.example.test/callback' };

export async function POST(request: Request) {
  const body = await request.json();
  return oauth.authorization.create({ redirect_uri: REDIRECT_URIS[body.client] });
}
