export async function createInvoice() {
  try {
    return Response.json(await database.invoice.create({ data: {} }));
  } catch (error) {
    logger.error({ error }, 'invoice creation failed');
    return Response.json({ code: 'INVOICE_FAILED' }, { status: 500 });
  }
}
