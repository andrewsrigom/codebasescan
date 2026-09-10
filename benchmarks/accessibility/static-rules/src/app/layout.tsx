/* eslint-disable @next/next/no-img-element, jsx-a11y/alt-text */
export default function Layout({ children }) {
  return (
    <html>
      <body>
        <img src="/logo.png" />
        <div onClick={() => save()}>Save</div>
        <input id="email" />
        {children}
      </body>
    </html>
  );
}
