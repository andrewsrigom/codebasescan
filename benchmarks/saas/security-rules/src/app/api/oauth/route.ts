export async function POST(request: Request) {
  const body = await request.json();
  return oauth.authorization.create({ redirect_uri: body.redirectUri });
}
