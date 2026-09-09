export function Preview({ html }: { html: string }) {
  return <article dangerouslySetInnerHTML={{ __html: html }} />;
}
