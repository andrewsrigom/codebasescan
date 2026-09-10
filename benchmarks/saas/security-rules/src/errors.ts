export async function createInvoice() {
  try {
    return Response.json(await database.invoice.create({ data: {} }));
  } catch (error) {
    return Response.json({ error: error.message, stack: error.stack });
  }
}
