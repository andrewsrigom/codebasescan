'use client';

export function Account() {
  return <div data-token={process.env.INTERNAL_API_TOKEN}>Account</div>;
}
