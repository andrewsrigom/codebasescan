'use client';

import { cookies } from 'next/headers';

export async function ClientPanel({ html, destination, session, token }) {
  localStorage.setItem('access_token', token);
  window.parent.postMessage({ token }, '*');
  window.addEventListener('message', (event) => consume(event.data));
  return (
    <>
      <a href={destination} target="_blank">
        Continue
      </a>
      <article dangerouslySetInnerHTML={{ __html: html }} />
      <div>{String(cookies) + session.user.name}</div>
    </>
  );
}
