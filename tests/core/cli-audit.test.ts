import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { execFile, spawnSync } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { once } from 'node:events';

const execute = promisify(execFile);

test('advisory policy output separates detected candidates from gated findings', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-cli-audit-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const repository = path.resolve('.');
  const result = spawnSync(
    process.execPath,
    [
      '--experimental-strip-types',
      path.join(repository, 'src/cli/main.ts'),
      'audit',
      path.join(repository, 'fixtures/review-worthy-saas'),
      '--report-dir',
      path.join(temporary, 'report'),
      '--policy',
      'advisory',
      '--non-interactive',
      '--quiet',
    ],
    {
      cwd: temporary,
      encoding: 'utf8',
      env: {
        ...process.env,
        CODEBASESCAN_SEMGREP: 'false',
        CODEBASESCAN_GITLEAKS: 'false',
      },
    },
  );
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(
    result.stderr,
    /Policy advisory: advisory; [1-9]\d* finding candidates; 0 gated findings; 0 blocking coverage issues\./,
  );
});

test('CLI probes only the explicit URL allowlist and keeps both observations', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-cli-probe-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const requested: string[] = [];
  const server = createServer((request, response) => {
    requested.push(request.url ?? '');
    response.writeHead(204, { 'X-Content-Type-Options': 'nosniff' });
    response.end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  context.after(() => server.close());
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Test server did not bind.');
  const origin = `http://127.0.0.1:${address.port}`;
  const repository = path.resolve('.');
  const destination = path.join(temporary, 'report');
  await execute(
    process.execPath,
    [
      path.join(repository, 'src/cli/main.ts'),
      'audit',
      path.join(repository, 'fixtures/review-worthy-saas'),
      '--report-dir',
      destination,
      '--modes',
      'security',
      '--probe-url',
      `${origin}/first`,
      '--probe-url',
      `${origin}/second`,
      '--non-interactive',
      '--quiet',
    ],
    {
      cwd: temporary,
      timeout: 60_000,
      env: { ...process.env, CODEBASESCAN_SEMGREP: 'false', CODEBASESCAN_GITLEAKS: 'false' },
    },
  );
  const report = JSON.parse(
    await readFile(path.join(destination, 'audit-report.json'), 'utf8'),
  ) as {
    httpProbe?: { requestedUrl: string };
    httpProbes?: { requestedUrl: string }[];
    scanners: { id: string; status: string }[];
  };
  assert.deepEqual(requested, ['/first', '/second']);
  assert.equal(report.httpProbe?.requestedUrl, `${origin}/first`);
  assert.deepEqual(
    report.httpProbes?.map((item) => item.requestedUrl),
    [`${origin}/first`, `${origin}/second`],
  );
  assert.equal(report.scanners.find((item) => item.id === 'http-probe')?.status, 'completed');
});
