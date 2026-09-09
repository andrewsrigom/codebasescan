import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { digest } from '../../src/domain/findings.ts';
import { resolvedInventory } from '../../src/scanners/inventory.ts';
import { cvssV3BaseScore, cvssV3Severity, scanOsv } from '../../src/scanners/osv.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import type { Snapshot } from '../../src/domain/types.ts';

function snapshot(files: Record<string, string>): Snapshot {
  const entries = Object.entries(files).map(([file, content]) => ({
    path: file,
    scope: 'runtime' as const,
    content,
    digest: digest(content),
    bytes: Buffer.byteLength(content),
  }));
  return {
    files: entries,
    digest: digest(entries.map((entry) => `${entry.path}:${entry.digest}`).join('\n')),
    totalBytes: entries.reduce((sum, entry) => sum + entry.bytes, 0),
    skipped: {},
    truncated: false,
  };
}

test('npm lockfile inventory uses resolved versions and direct/transitive relationships', () => {
  const source = snapshot({
    'package.json': '{"dependencies":{"alpha":"^1.0.0"}}',
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { alpha: '^1.0.0' } },
        'node_modules/alpha': { version: '1.2.3' },
        'node_modules/alpha/node_modules/beta': { version: '2.0.0' },
      },
    }),
  });
  const result = resolvedInventory(source).dependencies;
  assert.equal(result.find((item) => item.name === 'alpha')?.resolvedVersion, '1.2.3');
  assert.equal(result.find((item) => item.name === 'alpha')?.relationship, 'direct');
  assert.equal(result.find((item) => item.name === 'beta')?.relationship, 'transitive');
});

test('pnpm and Yarn lockfiles produce resolved package inventory', () => {
  const pnpm = resolvedInventory(
    snapshot({
      'package.json': '{"dependencies":{"alpha":"^1.0.0"}}',
      'pnpm-lock.yaml':
        "lockfileVersion: '9.0'\npackages:\n  alpha@1.2.3: {}\n  beta@2.0.0:\n    dev: true\n",
    }),
  );
  assert.equal(pnpm.dependencies.find((item) => item.name === 'alpha')?.resolvedVersion, '1.2.3');
  assert.equal(pnpm.dependencies.find((item) => item.name === 'beta')?.scope, 'development');

  const classic = resolvedInventory(
    snapshot({
      'package.json': '{"dependencies":{"alpha":"^1.0.0"}}',
      'yarn.lock': 'alpha@^1.0.0:\n  version "1.2.3"\n\nbeta@^2.0.0:\n  version "2.1.0"\n',
    }),
  );
  assert.equal(
    classic.dependencies.find((item) => item.name === 'alpha')?.resolvedVersion,
    '1.2.3',
  );
  assert.equal(
    classic.dependencies.find((item) => item.name === 'beta')?.relationship,
    'transitive',
  );

  const berry = resolvedInventory(
    snapshot({
      'package.json': '{"dependencies":{"alpha":"^1.0.0"}}',
      'yarn.lock': '__metadata:\n  version: 8\n"alpha@npm:^1.0.0":\n  version: 1.2.3\n',
    }),
  );
  assert.equal(berry.dependencies.find((item) => item.name === 'alpha')?.resolvedVersion, '1.2.3');
});

test('CVSS v3 vectors are scored without understating critical advisories', () => {
  assert.equal(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvssV3Severity('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 'critical');
  assert.equal(cvssV3BaseScore('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L'), 4.2);
  assert.equal(cvssV3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N'), null);
  assert.equal(cvssV3BaseScore('not-a-vector'), null);
});

test('OSV normalizes aliases, fixed versions, and provenance without exploitability claims', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-osv-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const source = await captureSnapshot(path.resolve('fixtures/dependencies-vulnerable'));
  const requests: { url: string; body?: string }[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = String(input);
    requests.push({ url, ...(typeof init?.body === 'string' ? { body: init.body } : {}) });
    if (url.endsWith('/querybatch'))
      return Response.json({ results: [{ vulns: [{ id: 'GHSA-fixture-1234' }] }] });
    return Response.json({
      id: 'GHSA-fixture-1234',
      aliases: ['CVE-2099-0001'],
      summary: 'Fixture package vulnerability',
      modified: '2099-01-01T00:00:00Z',
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      affected: [
        {
          package: { name: 'lodash' },
          ecosystem_specific: { severity: 'HIGH' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
        },
      ],
    });
  };
  const result = await scanOsv(source, true, path.join(directory, 'cache.json'), 24, undefined, {
    fetch: fetcher,
    now: () => Date.parse('2099-01-02T00:00:00Z'),
  });
  assert.equal(result.run.status, 'completed');
  assert.equal(result.findings[0]?.severity, 'high');
  assert.deepEqual(result.findings[0]?.vulnerability?.aliases, ['CVE-2099-0001']);
  assert.deepEqual(result.findings[0]?.vulnerability?.fixedVersions, ['4.17.21']);
  assert.match(result.findings[0]?.description ?? '', /not assessed/);
  assert.ok(requests[0]?.body?.includes('"name":"lodash"'));
  assert.ok(!requests[0]?.body?.includes('development-fallback'));

  let cachedCalls = 0;
  const cached = await scanOsv(source, true, path.join(directory, 'cache.json'), 24, undefined, {
    fetch: async () => {
      cachedCalls++;
      throw new Error('cache should avoid network');
    },
    now: () => Date.parse('2099-01-02T01:00:00Z'),
  });
  assert.equal(cached.run.status, 'completed');
  assert.equal(cached.findings.length, 1);
  assert.equal(cachedCalls, 0);
});

test('OSV clean and malformed responses remain distinct', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-osv-clean-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const source = await captureSnapshot(path.resolve('fixtures/dependencies-safe'));
  const clean = await scanOsv(source, true, path.join(directory, 'clean.json'), 24, undefined, {
    fetch: async () => Response.json({ results: [{}] }),
  });
  assert.equal(clean.run.status, 'completed');
  assert.equal(clean.findings.length, 0);
  const malformed = await scanOsv(
    source,
    true,
    path.join(directory, 'malformed.json'),
    24,
    undefined,
    { fetch: async () => Response.json({ results: [] }) },
  );
  assert.equal(malformed.run.status, 'failed');
  assert.match(malformed.run.detail, /count mismatch/);
});

test('OSV follows bounded per-query pagination', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-osv-pages-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const source = await captureSnapshot(path.resolve('fixtures/dependencies-vulnerable'));
  const bodies: string[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith('/querybatch')) {
      const body = typeof init?.body === 'string' ? init.body : '';
      bodies.push(body);
      return bodies.length === 1
        ? Response.json({
            results: [{ vulns: [{ id: 'GHSA-page-one' }], next_page_token: 'page-two' }],
          })
        : Response.json({ results: [{ vulns: [{ id: 'GHSA-page-two' }] }] });
    }
    const id = url.endsWith('GHSA-page-one') ? 'GHSA-page-one' : 'GHSA-page-two';
    return Response.json({
      id,
      summary: id,
      affected: [{ package: { name: 'lodash' }, ranges: [{ events: [] }] }],
    });
  };
  const result = await scanOsv(source, true, path.join(directory, 'cache.json'), 24, undefined, {
    fetch: fetcher,
  });
  assert.equal(result.run.status, 'completed');
  assert.deepEqual(
    result.findings.map((finding) => finding.ruleId),
    ['GHSA-page-one', 'GHSA-page-two'],
  );
  assert.equal(bodies.length, 2);
  assert.match(bodies[1] ?? '', /"page_token":"page-two"/);
});
