export async function issueRecovery() {
  const resetToken = crypto.randomUUID();
  return database.passwordReset.create({
    data: {
      tokenHash: hash(resetToken),
      expiresAt: new Date(Date.now() + 900_000),
    },
  });
}
