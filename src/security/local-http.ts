export function localRequestError(request: Request, port = '3000'): string | null {
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  const url = new URL(request.url);
  const host = request.headers.get('host') ?? url.host;
  if (!allowedHosts.has(host) || !allowedHosts.has(url.host))
    return 'Only loopback requests are accepted.';
  const origin = request.headers.get('origin');
  if (origin && origin !== `http://${host}`) return 'Cross-origin requests are not accepted.';
  if (request.headers.get('sec-fetch-site') === 'cross-site')
    return 'Cross-site requests are not accepted.';
  if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
    if (origin !== `http://${host}` || request.headers.get('x-traceward-client') !== 'local-ui')
      return 'A same-origin UI request is required.';
    if (!request.headers.get('content-type')?.startsWith('application/json'))
      return 'JSON is required.';
  }
  return null;
}
export async function boundedJson(request: Request, maximumBytes = 16384): Promise<unknown> {
  if (!request.body) throw new Error('A request body is required.');
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel();
        throw new Error('Request body is too large.');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}
