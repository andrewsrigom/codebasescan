'use client';

export function SafeLink({ label }: { label: string }) {
  window.parent.postMessage({ ready: true }, 'https://app.example.test');
  window.addEventListener('message', (event) => {
    if (event.origin !== 'https://app.example.test') return;
    consume(event.data);
  });
  return (
    <a href="/account" rel="noopener noreferrer" target="_blank">
      {label}
    </a>
  );
}
