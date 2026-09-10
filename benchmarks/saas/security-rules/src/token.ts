export function issueResetToken() {
  const resetToken = `${Date.now()}-${Math.random()}`;
  return resetToken;
}
