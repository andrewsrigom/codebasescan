import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises';
import {
  safeRelative,
  isWithin,
  classifySourceScope,
  captureSnapshot,
  estimateProjectScope,
  snapshotLimits,
  validateProjectRoot,
} from '../../src/security/paths.ts';
import { redact } from '../../src/security/redact.ts';
import { boundedJson, localRequestError } from '../../src/security/local-http.ts';
import {
  auditOptions,
  controlReviewDecision,
  reviewDecision,
  suppressionDecision,
  uuid,
} from '../../src/domain/validation.ts';
for (const input of [
  '../secret',
  '/etc/passwd',
  'C:\\private\\file',
  'a/../../b',
  'a\\..\\b',
  './file',
  'bad\0path',
]) {
  test(`rejects unsafe relative path ${JSON.stringify(input)}`, () =>
    assert.throws(() => safeRelative(input)));
}
test('allows contained source paths but not sibling prefix tricks', () => {
  assert.equal(safeRelative('src/app/page.tsx'), 'src/app/page.tsx');
  assert.equal(isWithin('/work/repo', '/work/repository/file.ts'), false);
  assert.equal(isWithin('/work/repo', '/work/repo/src/file.ts'), true);
});
test('classifies runtime, test, and example source scopes', () => {
  assert.equal(classifySourceScope('src/app/api/users/route.ts'), 'runtime');
  assert.equal(classifySourceScope('src/users.spec.ts'), 'test');
  assert.equal(classifySourceScope('fixtures/express/package.json'), 'test');
  assert.equal(classifySourceScope('src/test-utils/axe.ts'), 'test');
  assert.equal(classifySourceScope('src/domain-test-helpers.ts'), 'test');
  assert.equal(classifySourceScope('src/test-figma-node.ts'), 'test');
  assert.equal(classifySourceScope('src/token-test-fixtures.ts'), 'test');
  assert.equal(classifySourceScope('e2e/workspace.spec.ts'), 'test');
  assert.equal(classifySourceScope('.storybook/preview.ts'), 'example');
  assert.equal(classifySourceScope('examples/insecure.ts'), 'example');
});
test('redacts credential assignments and connection-string passwords', () => {
  const input =
    'const apiKey = "not-a-real-credential"; const url="postgres://user:private-password@db/example";';
  const output = redact(input);
  assert.ok(!output.includes('not-a-real-credential'));
  assert.ok(!output.includes('private-password'));
  assert.ok(output.includes('[REDACTED]'));
});
test('redacts multiline private-key material', () => {
  assert.equal(
    redact('-----BEGIN PRIVATE KEY-----\nFAKE TEST MATERIAL\n-----END PRIVATE KEY-----'),
    '[REDACTED PRIVATE KEY]',
  );
});
test('same-origin JSON mutation is permitted', () => {
  const request = new Request('http://127.0.0.1:3000/api/audits', {
    method: 'POST',
    headers: {
      host: '127.0.0.1:3000',
      origin: 'http://127.0.0.1:3000',
      'content-type': 'application/json',
      'x-codebasescan-client': 'local-ui',
    },
    body: '{}',
  });
  assert.equal(localRequestError(request), null);
});
test('cross-origin requests and DNS-rebinding hosts are rejected', () => {
  assert.ok(
    localRequestError(
      new Request('http://127.0.0.1:3000/api/audits', {
        headers: { origin: 'https://attacker.invalid' },
      }),
    ),
  );
  assert.ok(localRequestError(new Request('http://attacker.invalid:3000/api/audits')));
  assert.ok(
    localRequestError(
      new Request('http://127.0.0.1:3000/api/audits', {
        headers: { 'sec-fetch-site': 'cross-site' },
      }),
    ),
  );
});
test('an explicit internal relay host still requires a loopback browser host', () => {
  const internalHost = '172.19.23.77:3000';
  assert.equal(
    localRequestError(
      new Request(`http://${internalHost}/api/audits`, {
        headers: { host: '127.0.0.1:3000' },
      }),
      '3000',
      internalHost,
    ),
    null,
  );
  assert.ok(
    localRequestError(
      new Request(`http://${internalHost}/api/audits`, {
        headers: { host: internalHost },
      }),
      '3000',
      internalHost,
    ),
  );
});
test('mutations without the explicit UI header are rejected', () => {
  assert.ok(
    localRequestError(
      new Request('http://127.0.0.1:3000/api/audits', {
        method: 'POST',
        headers: { origin: 'http://127.0.0.1:3000', 'content-type': 'application/json' },
        body: '{}',
      }),
    ),
  );
});
test('request body limit is enforced even without a Content-Length header', async () => {
  await assert.rejects(
    () =>
      boundedJson(
        new Request('http://127.0.0.1:3000/', { method: 'POST', body: 'x'.repeat(200) }),
        100,
      ),
    /too large/,
  );
  assert.deepEqual(
    await boundedJson(
      new Request('http://127.0.0.1:3000/', { method: 'POST', body: '{"ok":true}' }),
    ),
    { ok: true },
  );
});
test('human decisions require an explanation and valid disposition', () => {
  assert.throws(() => reviewDecision({ findingId: 'x', disposition: 'confirmed', note: 'yes' }));
  assert.throws(() =>
    reviewDecision({ findingId: 'x', disposition: 'safe', note: 'Long enough explanation.' }),
  );
  assert.equal(
    reviewDecision({
      findingId: 'x',
      disposition: 'needs_review',
      note: 'Runtime access control is still unknown.',
    }).disposition,
    'needs_review',
  );
  assert.equal(
    reviewDecision({
      findingId: 'x',
      disposition: 'fixed',
      note: 'A regression test verifies the corrected trust boundary.',
    }).disposition,
    'fixed',
  );
  assert.throws(() => uuid('../../etc/passwd'));
});
test('control reviews require a known decision and meaningful rationale', () => {
  assert.throws(() =>
    controlReviewDecision({
      controlId: 'TW-CTRL-AUTHN-001',
      decision: 'safe',
      note: 'Enough context here.',
    }),
  );
  assert.throws(() =>
    controlReviewDecision({
      controlId: 'TW-CTRL-AUTHN-001',
      decision: 'verified_external',
      note: 'short',
    }),
  );
  assert.equal(
    controlReviewDecision({
      controlId: 'TW-CTRL-AUTHN-001',
      decision: 'verified_external',
      note: 'Gateway policy was inspected and tested.',
    }).decision,
    'verified_external',
  );
});
test('HTTP probe options require explicit approval', () => {
  assert.throws(
    () => auditOptions({ httpProbe: { url: 'http://127.0.0.1:3000/' } }),
    /explicitly approved/,
  );
  assert.equal(
    auditOptions({
      httpProbe: {
        url: 'http://127.0.0.1:3000/',
        approved: true,
        allowPrivateNetwork: false,
      },
    }).httpProbe?.url,
    'http://127.0.0.1:3000/',
  );
});
test('Git history secret scanning requires an explicit boolean option', () => {
  assert.throws(() => auditOptions({ gitHistorySecrets: 'yes' }), /must be a boolean/);
  assert.equal(auditOptions({ gitHistorySecrets: true }).gitHistorySecrets, true);
  assert.equal(auditOptions({}).gitHistorySecrets, undefined);
});
test('audit modes are bounded, known, and deduplicated', () => {
  assert.deepEqual(auditOptions({ modes: ['security', 'privacy', 'privacy'] }).modes, [
    'security',
    'privacy',
  ]);
  assert.throws(() => auditOptions({ modes: [] }), /non-empty bounded list/);
  assert.throws(() => auditOptions({ modes: ['unknown'] }), /Unknown audit mode/);
});
test('project exceptions require rationale and a future expiry', () => {
  assert.throws(
    () => suppressionDecision({ findingId: 'finding', reason: 'too short' }),
    /at least 12/,
  );
  assert.throws(
    () =>
      suppressionDecision({
        findingId: 'finding',
        reason: 'Reviewed exception reason.',
        expiresAt: '2000-01-01T00:00:00.000Z',
      }),
    /future ISO date/,
  );
  assert.equal(
    suppressionDecision({
      findingId: 'finding',
      reason: 'Reviewed exception reason.',
      expiresAt: '2099-01-01',
    }).expiresAt,
    '2099-01-01T00:00:00.000Z',
  );
});
test('snapshot skips sensitive files, symlinks and generated trees', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-source-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'node_modules'));
  await mkdir(path.join(root, '.next-dev'));
  await mkdir(path.join(root, 'codebasescan-report'));
  await mkdir(path.join(root, '.pnpm-store'));
  await mkdir(path.join(root, 'out'));
  await mkdir(path.join(root, 'output'));
  await mkdir(path.join(root, 'storybook-static'));
  await mkdir(path.join(root, '_pagefind'));
  await mkdir(path.join(root, 'test-results'));
  await writeFile(path.join(root, 'source.ts'), 'export const ok = true;');
  await writeFile(path.join(root, 'schema.prisma'), 'model User { id String @id }');
  await writeFile(path.join(root, '.env'), 'SECRET=fixture');
  await writeFile(
    path.join(root, '.env.example'),
    'PUBLIC_URL=https://example.test\nSECRET_TOKEN=must-not-be-retained\n',
  );
  await writeFile(path.join(root, '.env.production.sample'), 'DATABASE_URL=private-value\n');
  await writeFile(path.join(root, 'node_modules', 'ignored.ts'), 'eval(input)');
  await writeFile(path.join(root, '.next-dev', 'generated.js'), 'eval(input)');
  await writeFile(path.join(root, 'codebasescan-report', 'audit-report.json'), '{"ignored":true}');
  await writeFile(path.join(root, '.pnpm-store', 'generated.js'), 'eval(input)');
  await writeFile(path.join(root, 'out', 'generated.js'), 'eval(input)');
  await writeFile(path.join(root, 'output', 'generated.js'), 'eval(input)');
  await writeFile(path.join(root, 'storybook-static', 'generated.js'), 'eval(input)');
  await writeFile(path.join(root, '_pagefind', 'generated.js'), 'eval(input)');
  await writeFile(path.join(root, 'test-results', 'generated.js'), 'eval(input)');
  if (process.platform !== 'win32') await symlink('/etc/passwd', path.join(root, 'outside.ts'));
  const snapshot = await captureSnapshot(root);
  assert.deepEqual(
    snapshot.files.map((file) => file.path),
    ['.env.example', '.env.production.sample', 'schema.prisma', 'source.ts'],
  );
  assert.equal(
    snapshot.files.find((file) => file.path === '.env.example')?.content,
    'PUBLIC_URL=\nSECRET_TOKEN=\n',
  );
  assert.equal(
    snapshot.files.find((file) => file.path === '.env.production.sample')?.content,
    'DATABASE_URL=\n',
  );
  assert.equal(JSON.stringify(snapshot).includes('must-not-be-retained'), false);
  assert.equal(JSON.stringify(snapshot).includes('private-value'), false);
  assert.equal(snapshot.skipped['sensitive-file'], 1);
  if (process.platform !== 'win32') assert.equal(snapshot.skipped['symbolic-link'], 1);
});
test('snapshot records source scope without excluding secret-bearing test code', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-scope-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'tests'));
  await mkdir(path.join(root, 'examples'));
  await writeFile(path.join(root, 'app.ts'), 'export const app = true;');
  await writeFile(path.join(root, 'tests', 'app.test.ts'), 'export const test = true;');
  await writeFile(path.join(root, 'examples', 'demo.ts'), 'export const demo = true;');
  const snapshot = await captureSnapshot(root);
  const estimate = await estimateProjectScope(root);
  assert.deepEqual(Object.fromEntries(snapshot.files.map((file) => [file.path, file.scope])), {
    'app.ts': 'runtime',
    'examples/demo.ts': 'example',
    'tests/app.test.ts': 'test',
  });
  assert.deepEqual(estimate.scopeFiles, { runtime: 1, test: 1, example: 1 });
});
test('project gitignore rules exclude local artifacts while preserving exceptions', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-gitignore-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'ignored'));
  await writeFile(
    path.join(root, '.gitignore'),
    'ignored/\n*.generated.ts\n!important.generated.ts\n',
  );
  await writeFile(path.join(root, 'source.ts'), 'export const source = true;');
  await writeFile(path.join(root, 'discard.generated.ts'), 'eval(input)');
  await writeFile(path.join(root, 'important.generated.ts'), 'export const retained = true;');
  await writeFile(path.join(root, 'ignored', 'artifact.ts'), 'eval(input)');
  const snapshot = await captureSnapshot(root);
  const estimate = await estimateProjectScope(root);
  assert.deepEqual(
    snapshot.files.map((file) => file.path),
    ['important.generated.ts', 'source.ts'],
  );
  assert.equal(snapshot.skipped['gitignored-path'], 2);
  assert.equal(estimate.supportedFiles, 2);
  assert.equal(estimate.predictedTruncated, false);
});
test('snapshot excludes conventional generated output directories', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-generated-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  for (const directory of ['generated', '__generated__', '.generated']) {
    await mkdir(path.join(root, directory));
    await writeFile(path.join(root, directory, 'client.ts'), 'eval(input)');
  }
  await writeFile(path.join(root, 'source.ts'), 'export const source = true;');
  const snapshot = await captureSnapshot(root);
  const estimate = await estimateProjectScope(root);
  assert.deepEqual(
    snapshot.files.map((file) => file.path),
    ['source.ts'],
  );
  assert.equal(snapshot.skipped['excluded-directory'], 3);
  assert.equal(estimate.supportedFiles, 1);
  assert.equal(estimate.predictedTruncated, false);
});
test('large files are excluded and coverage is marked truncated', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-large-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, 'large.ts'), 'a'.repeat(snapshotLimits.bytesPerFile + 1));
  const snapshot = await captureSnapshot(root);
  const estimate = await estimateProjectScope(root);
  assert.equal(snapshot.truncated, true);
  assert.equal(snapshot.files.length, 0);
  assert.equal(estimate.supportedFiles, 1);
  assert.equal(estimate.oversizedFiles, 1);
  assert.equal(estimate.predictedTruncated, true);
  assert.deepEqual(estimate.reasons, ['per-file-byte-limit']);
});
test('snapshot captures only conventional text web posture artifacts', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-web-files-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'public'));
  await writeFile(path.join(root, 'public', 'robots.txt'), 'User-agent: *\nAllow: /\n');
  await writeFile(path.join(root, 'public', 'sitemap.xml'), '<urlset />');
  await writeFile(path.join(root, 'public', 'llms.txt'), '# Product\n');
  await writeFile(path.join(root, 'public', 'notes.txt'), 'not an audit input');
  const snapshot = await captureSnapshot(root);
  assert.deepEqual(
    snapshot.files.map((file) => file.path),
    ['public/llms.txt', 'public/robots.txt', 'public/sitemap.xml'],
  );
});
test('large generated TypeScript modules within the bounded limit are retained', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-large-source-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(
    path.join(root, 'generated.ts'),
    `export const value = '${'a'.repeat(300_000)}';`,
  );
  const snapshot = await captureSnapshot(root);
  const estimate = await estimateProjectScope(root);
  assert.equal(snapshot.files[0]?.path, 'generated.ts');
  assert.equal(snapshot.truncated, false);
  assert.equal(estimate.oversizedFiles, 0);
  assert.equal(estimate.limits.bytesPerFile, snapshotLimits.bytesPerFile);
});
test('realistic lockfiles use a separate bounded size allowance', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-lockfile-size-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  const content = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      'node_modules/example': { version: '1.0.0', padding: 'a'.repeat(300_000) },
    },
  });
  await writeFile(path.join(root, 'package-lock.json'), content);
  const snapshot = await captureSnapshot(root);
  const estimate = await estimateProjectScope(root);
  assert.equal(snapshot.files[0]?.path, 'package-lock.json');
  assert.equal(snapshot.truncated, false);
  assert.equal(estimate.oversizedFiles, 0);
  assert.equal(estimate.limits.lockfileBytes, 4 * 1024 * 1024);
});
test('bounded coverage summaries are captured without traversing generated coverage output', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-coverage-artifact-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'coverage'));
  await writeFile(path.join(root, 'coverage', 'coverage-summary.json'), '{"total":{}}');
  await writeFile(path.join(root, 'coverage', 'lcov.info'), 'LF:1\nLH:1\n');
  await writeFile(path.join(root, 'coverage', 'generated.json'), '{"must":"stay excluded"}');
  const snapshot = await captureSnapshot(root);
  const estimate = await estimateProjectScope(root);
  assert.deepEqual(
    snapshot.files.map((file) => file.path),
    ['coverage/coverage-summary.json', 'coverage/lcov.info'],
  );
  assert.ok(snapshot.files.every((file) => file.scope === 'test'));
  assert.equal(estimate.supportedFiles, 2);
});
test('registration rejects home and overlapping audit storage', async (context) => {
  await assert.rejects(() => validateProjectRoot(os.homedir(), path.join(os.tmpdir(), 'tw-state')));
  const root = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-root-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await assert.rejects(
    () => validateProjectRoot(root, path.join(root, '.codebasescan')),
    /overlap/,
  );
});
