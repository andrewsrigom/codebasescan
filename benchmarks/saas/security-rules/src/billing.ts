export async function createCheckout(request: Request) {
  const body = await request.json();
  return stripe.checkout.sessions.create({
    line_items: [{ price: body.priceId }],
  });
}
