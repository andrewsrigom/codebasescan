export async function issueRecovery() {
  const resetToken = crypto.randomUUID();
  return database.passwordReset.create({ data: { resetToken } });
}
