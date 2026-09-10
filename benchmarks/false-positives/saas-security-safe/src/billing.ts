const PRICE_IDS = { starter: 'price_server_owned' };

export async function createCheckout(request: Request) {
  const body = await request.json();
  return stripe.checkout.sessions.create({
    line_items: [{ price: PRICE_IDS[body.plan] }],
  });
}
