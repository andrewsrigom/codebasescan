import { randomBytes } from 'node:crypto';

export function issueResetToken() {
  const resetToken = randomBytes(32).toString('hex');
  return resetToken;
}
