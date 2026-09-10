export async function POST() {
  const resetToken = crypto.randomUUID();
  return database.passwordReset.create({ data: { resetToken } });
}
