/* eslint-disable @next/next/no-img-element */
export function Form() {
  const params = new URLSearchParams();
  params.set('theme', 'dark');
  logger.info({ email: redact(email) });
  localStorage.setItem('theme', 'dark');
  return (
    <>
      <img src="/shape.png" alt="" />
      <button onClick={() => save()}>Save</button>
      <label htmlFor="email">Email</label>
      <input id="email" />
    </>
  );
}
