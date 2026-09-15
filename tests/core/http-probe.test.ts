import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type RequestListener, type Server } from 'node:http';
import { once } from 'node:events';
import { validateProbeUrl } from '../../src/security/url-policy.ts';
import {
  probeHttp,
  probeHttpAllowlist,
  reconcileHttpPosture,
} from '../../src/scanners/http-probe.ts';
import { snapshotOf } from '../helpers.ts';
import { scanPosture } from '../../src/scanners/posture.ts';
import { sampleReport } from '../helpers.ts';
import { parseAuditReport } from '../../src/domain/report-schema.ts';

async function localServer(handler: RequestListener): Promise<{
  server: Server;
  url: string;
}> {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Test server did not bind.');
  return { server, url: `http://127.0.0.1:${address.port}/` };
}

test('URL policy blocks metadata, credentials, unsafe schemes, and private DNS by default', async () => {
  await assert.rejects(
    () => validateProbeUrl('http://169.254.169.254/', true),
    /blocked|forbidden/,
  );
  await assert.rejects(
    () => validateProbeUrl('http://[fd00:ec2::254]/', true),
    /blocked|forbidden/,
  );
  await assert.rejects(() => validateProbeUrl('file:///etc/passwd', false), /http or https/);
  await assert.rejects(
    () => validateProbeUrl('http://user:password@example.test/', false),
    /credentials/,
  );
  await assert.rejects(
    () => validateProbeUrl('https://example.test/?api_key=fixture', false),
    /credential-shaped/,
  );
  const privateResolver = async () => [{ address: '192.168.1.20', family: 4 }];
  await assert.rejects(
    () => validateProbeUrl('http://stage.example.test/', false, privateResolver),
    /explicit allowPrivateNetwork/,
  );
  assert.equal(
    (await validateProbeUrl('http://stage.example.test/', true, privateResolver)).addresses[0]
      ?.address,
    '192.168.1.20',
  );
});

test('probe uses a bounded HEAD request and discards cookie values', async (context) => {
  const methods: string[] = [];
  const origins: (string | undefined)[] = [];
  const { server, url } = await localServer((request, response) => {
    methods.push(request.method ?? '');
    origins.push(request.headers.origin);
    response.writeHead(200, {
      'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-eval'",
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': 'true',
      'Set-Cookie': 'session=never-store-this-value; Path=/',
    });
    response.end();
  });
  context.after(() => server.close());
  const result = await probeHttp({ url, allowPrivateNetwork: false });
  assert.equal(result.run.status, 'completed');
  assert.deepEqual(methods, ['HEAD']);
  assert.deepEqual(origins, ['https://codebasescan.invalid']);
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-H002'));
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-H003'));
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-H004'));
  assert.ok(!JSON.stringify(result).includes('never-store-this-value'));
});

test('explicit allowlist keeps each observation and partial failures separate', async (context) => {
  const paths: string[] = [];
  const { server, url } = await localServer((request, response) => {
    paths.push(request.url ?? '');
    response.writeHead(204, { 'X-Content-Type-Options': 'nosniff' });
    response.end();
  });
  context.after(() => server.close());
  const result = await probeHttpAllowlist([
    { url: new URL('/one', url).toString(), allowPrivateNetwork: false },
    { url: 'file:///not-http', allowPrivateNetwork: false },
    { url: new URL('/two', url).toString(), allowPrivateNetwork: false },
  ]);
  assert.equal(result.run.status, 'partial');
  assert.equal(result.reports.length, 2);
  assert.deepEqual(paths, ['/one', '/two']);
  const report = sampleReport();
  report.httpProbe = result.reports[0];
  report.httpProbes = result.reports;
  assert.equal(parseAuditReport(report).httpProbes?.length, 2);
  await assert.rejects(
    () => probeHttpAllowlist(Array(4).fill({ url, allowPrivateNetwork: false })),
    /exceeds three/,
  );
});

test('passive observation covers reflected CORS, shared cache, and broad script CSP', async (context) => {
  const { server, url } = await localServer((request, response) => {
    response.writeHead(200, {
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=()',
      'Access-Control-Allow-Origin': request.headers.origin ?? '',
      'Access-Control-Allow-Credentials': 'true',
      'Cache-Control': 'public, s-maxage=300',
      'Set-Cookie': 'session=discarded; Secure; HttpOnly; SameSite=Lax',
    });
    response.end();
  });
  context.after(() => server.close());
  const result = await probeHttp({ url, allowPrivateNetwork: false });
  const ids = new Set(result.findings.map((finding) => finding.ruleId));
  assert.ok(ids.has('TW-H005'));
  assert.ok(ids.has('TW-H006'));
  assert.ok(ids.has('TW-H007'));
  assert.ok(ids.has('TW-H008'));
  assert.ok(!ids.has('TW-H004'));
  assert.equal(result.report?.headers['cache-control'], 'public, s-maxage=300');
});

test('redirect chain is retained as bounded passive evidence', async (context) => {
  const { server, url } = await localServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(302, { Location: '/final' });
      response.end();
      return;
    }
    response.writeHead(204, {
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=()',
    });
    response.end();
  });
  context.after(() => server.close());
  const result = await probeHttp({ url, allowPrivateNetwork: false });
  assert.equal(result.report?.redirectChain?.length, 1);
  assert.equal(result.report?.redirectChain?.[0]?.statusCode, 302);
  assert.match(result.report?.finalUrl ?? '', /\/final$/);
});

test('approved HTML response exposes bounded form and endpoint metadata', async (context) => {
  const methods: string[] = [];
  const { server, url } = await localServer((request, response) => {
    methods.push(request.method ?? '');
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    response.end(`
      <form method="get" action="/login?returnTo=private-value">
        <input type="password" name="password" value="never-retain-this" />
      </form>
      <form method="post" action="https://payments.example/checkout?token=discarded">
        <input name="amount" />
      </form>
    `);
  });
  context.after(() => server.close());
  const result = await probeHttp({ url, allowPrivateNetwork: false });
  assert.deepEqual(methods, ['HEAD', 'GET']);
  assert.equal(result.report?.htmlSurface?.formsObserved, 2);
  assert.equal(result.report?.htmlSurface?.formsRetained, 2);
  assert.equal(result.report?.htmlSurface?.formEndpoints[0]?.relationship, 'same-origin');
  assert.equal(result.report?.htmlSurface?.formEndpoints[1]?.relationship, 'cross-origin');
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-H010'));
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-H011'));
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-H012'));
  assert.ok(!JSON.stringify(result).includes('private-value'));
  assert.ok(!JSON.stringify(result).includes('never-retain-this'));
  assert.ok(!JSON.stringify(result).includes('discarded'));
});

test('probe accepts a complete response without inventing a security result', async (context) => {
  const { server, url } = await localServer((_request, response) => {
    response.writeHead(204, {
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'camera=()',
    });
    response.end();
  });
  context.after(() => server.close());
  const result = await probeHttp({ url, allowPrivateNetwork: false });
  assert.equal(result.run.status, 'completed');
  assert.equal(result.findings.length, 0);
  assert.equal(result.report?.statusCode, 204);
});

test('every redirect target is validated before it is requested', async (context) => {
  const { server, url } = await localServer((_request, response) => {
    response.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
    response.end();
  });
  context.after(() => server.close());
  const result = await probeHttp({ url, allowPrivateNetwork: false });
  assert.equal(result.run.status, 'failed');
  assert.match(result.run.detail, /blocked|forbidden/);
});

test('timeout and response-size failures are explicit', async (context) => {
  const hanging = await localServer(() => undefined);
  context.after(() => {
    hanging.server.closeAllConnections();
    hanging.server.close();
  });
  const timeout = await probeHttp({ url: hanging.url, allowPrivateNetwork: false }, undefined, {
    requestTimeoutMs: 50,
  });
  assert.equal(timeout.run.status, 'failed');

  const large = await localServer((request, response) => {
    if (request.method === 'HEAD') {
      response.writeHead(405);
      response.end();
      return;
    }
    response.writeHead(200);
    response.end('x'.repeat(4096));
  });
  context.after(() => large.server.close());
  const oversized = await probeHttp({ url: large.url, allowPrivateNetwork: false }, undefined, {
    responseLimitBytes: 1024,
  });
  assert.equal(oversized.run.status, 'failed');
  assert.match(oversized.run.detail, /size limit/);
});

test('runtime evidence is reconciled with a related static posture candidate', async (context) => {
  const source = snapshotOf(
    "export default { async headers() { return [{ headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] }] } }",
    'next.config.ts',
  );
  source.files.push({
    path: 'package.json',
    scope: 'runtime',
    content: '{"dependencies":{"next":"16.3.4"}}',
    digest: 'manifest',
    bytes: 34,
  });
  const staticFindings = scanPosture(source);
  assert.ok(staticFindings.some((finding) => finding.ruleId === 'TW-P001'));
  const { server, url } = await localServer((_request, response) => {
    response.writeHead(204, { 'X-Content-Type-Options': 'nosniff' });
    response.end();
  });
  context.after(() => server.close());
  const runtime = await probeHttp({ url, allowPrivateNetwork: false });
  const reconciled = reconcileHttpPosture([...staticFindings, ...runtime.findings], runtime.report);
  assert.equal(
    reconciled.some((finding) => finding.ruleId === 'TW-H001'),
    false,
  );
  const candidate = reconciled.find((finding) => finding.ruleId === 'TW-P001');
  assert.equal(candidate?.runtimeVerification?.status, 'corroborated');
  assert.ok(candidate?.evidence.some((evidence) => evidence.kind === 'observed'));
});

test('a later URL cannot be attributed to the first runtime observation', async (context) => {
  const source = snapshotOf(
    "export default { async headers() { return [{ headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] }] } }",
    'next.config.ts',
  );
  source.files.push({
    path: 'package.json',
    scope: 'runtime',
    content: '{"dependencies":{"next":"16.3.4"}}',
    digest: 'manifest',
    bytes: 34,
  });
  const staticFindings = scanPosture(source);
  const { server, url } = await localServer((request, response) => {
    response.writeHead(
      204,
      request.url === '/safe'
        ? {
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'camera=()',
          }
        : {},
    );
    response.end();
  });
  context.after(() => server.close());
  const result = await probeHttpAllowlist([
    { url: new URL('/safe', url).toString(), allowPrivateNetwork: false },
    { url: new URL('/weak', url).toString(), allowPrivateNetwork: false },
  ]);
  const reconciled = reconcileHttpPosture(
    [...staticFindings, ...result.findings],
    result.reports[0],
  );
  const staticCandidate = reconciled.find((finding) => finding.ruleId === 'TW-P001');
  const laterRuntime = reconciled.find((finding) => finding.ruleId === 'TW-H001');
  assert.equal(staticCandidate?.runtimeVerification?.status, 'observed_safe');
  assert.equal(staticCandidate?.runtimeVerification?.url, result.reports[0]?.finalUrl);
  assert.equal(laterRuntime?.evidence[0]?.url, result.reports[1]?.finalUrl);
});
