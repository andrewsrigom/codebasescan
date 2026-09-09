const authSecret = process.env.AUTH_SECRET;
if (!authSecret) throw new Error('AUTH_SECRET is required.');
export { authSecret };
