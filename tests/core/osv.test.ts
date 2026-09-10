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
        "lockfileVersion: '9.0'\npackages:\n  alpha@1.2.3: {}\n  beta@2.0.0:\n    dev: true\n  '@aws-crypto/crc32@5.2.0': {}\n  /@legacy/scoped/3.2.1: {}\n",
    }),
  );
  assert.equal(pnpm.dependencies.find((item) => item.name === 'alpha')?.resolvedVersion, '1.2.3');
  assert.equal(pnpm.dependencies.find((item) => item.name === 'beta')?.scope, 'development');
  assert.equal(
    pnpm.dependencies.find((item) => item.name === '@aws-crypto/crc32')?.resolvedVersion,
    '5.2.0',
  );
  assert.equal(
    pnpm.dependencies.find((item) => item.name === '@legacy/scoped')?.resolvedVersion,
    '3.2.1',
  );
  assert.equal(
    pnpm.dependencies.some((item) => item.name === '@aws-crypto'),
    false,
  );

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

test('pnpm inventory records bounded direct-parent chains without executing configuration', () => {
  const result = resolvedInventory(
    snapshot({
      'package.json': '{"dependencies":{"alpha":"1.2.3"}}',
      'pnpm-lock.yaml': `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alpha:
        specifier: 1.2.3
        version: 1.2.3
packages:
  alpha@1.2.3: {}
  beta@2.0.0: {}
  gamma@3.0.0: {}
snapshots:
  alpha@1.2.3(peer@9.0.0):
    dependencies:
      beta: 2.0.0
  beta@2.0.0:
    dependencies:
      gamma: 3.0.0
  gamma@3.0.0: {}
`,
    }),
  ).dependencies;
  assert.deepEqual(result.find((item) => item.name === 'alpha')?.parentChains, [
    ['package.json', 'alpha@1.2.3'],
  ]);
  assert.deepEqual(result.find((item) => item.name === 'gamma')?.parentChains, [
    ['package.json', 'alpha@1.2.3', 'beta@2.0.0', 'gamma@3.0.0'],
  ]);
  assert.equal(result.find((item) => item.name === 'gamma')?.relationship, 'transitive');
});

test('workspace lockfiles exclude local packages but retain direct external dependencies', () => {
  const npm = resolvedInventory(
    snapshot({
      'package.json': '{"workspaces":["packages/*"]}',
      'packages/app/package.json': '{"name":"@acme/app","dependencies":{"lodash":"^4.17.0"}}',
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { workspaces: ['packages/*'] },
          'packages/app': {
            name: '@acme/app',
            version: '1.0.0',
            dependencies: { lodash: '^4.17.0' },
          },
          'node_modules/@acme/app': { resolved: 'packages/app', link: true },
          'node_modules/lodash': { version: '4.17.21' },
        },
      }),
    }),
  ).dependencies;
  assert.equal(
    npm.some((item) => item.name === '@acme/app'),
    false,
  );
  assert.equal(npm.find((item) => item.name === 'lodash')?.relationship, 'direct');
  assert.equal(npm.find((item) => item.name === 'lodash')?.manifest, 'packages/app/package.json');

  const yarn = resolvedInventory(
    snapshot({
      'package.json': '{"dependencies":{"alpha":"^1.0.0"}}',
      'yarn.lock':
        '__metadata:\n  version: 8\n"@acme/app@workspace:packages/app":\n  version: 0.0.0-use.local\n  resolution: "@acme/app@workspace:packages/app"\n"alpha@npm:^1.0.0":\n  version: 1.2.3\n',
    }),
  ).dependencies;
  assert.equal(
    yarn.some((item) => item.name === '@acme/app'),
    false,
  );
  assert.equal(yarn.find((item) => item.name === 'alpha')?.resolvedVersion, '1.2.3');
});

test('CVSS v3 vectors are scored without understating critical advisories', () => {
  assert.equal(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvssV3Severity('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 'critical');
  assert.equal(cvssV3BaseScore('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L'), 4.2);
  assert.equal(cvssV3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N'), null);
  assert.equal(cvssV3BaseScore('not-a-vector'), null);
});

test('OSV normalizes aliases, fixed versions, and provenance without exploitability claims', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-osv-'));
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
      affected: [
        {
          package: { name: 'lodash' },
          severity: [
            {
              type: 'CVSS_V3',
              score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            },
          ],
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
  assert.equal(result.findings[0]?.severity, 'critical');
  assert.equal(result.findings[0]?.vulnerability?.severity[0]?.type, 'CVSS_V3');
  assert.deepEqual(result.findings[0]?.vulnerability?.aliases, ['CVE-2099-0001']);
  assert.deepEqual(result.findings[0]?.vulnerability?.fixedVersions, ['4.17.21']);
  assert.equal(result.findings[0]?.vulnerability?.reachability, 'not_found');
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

  const offline = await scanOsv(source, false, path.join(directory, 'cache.json'), 24);
  assert.equal(offline.run.status, 'completed');
  assert.equal(offline.findings.length, 1);
  assert.match(offline.run.detail, /without network access/);
});

test('dependency reachability records an explicit runtime import without claiming execution', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-osv-reference-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const source = snapshot({
    'package.json': '{"dependencies":{"fixture-package":"1.0.0"}}',
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'fixture-package': '1.0.0' } },
        'node_modules/fixture-package': { version: '1.0.0' },
      },
    }),
    'src/runtime.ts': `import { parse } from 'fixture-package/parser';\nexport const value = parse(input);`,
  });
  const fetcher: typeof fetch = async (input) =>
    String(input).endsWith('/querybatch')
      ? Response.json({ results: [{ vulns: [{ id: 'GHSA-reachable-fixture' }] }] })
      : Response.json({
          id: 'GHSA-reachable-fixture',
          summary: 'Reachability fixture',
          affected: [{ package: { name: 'fixture-package' }, ranges: [] }],
        });
  const result = await scanOsv(source, true, path.join(directory, 'database.json'), 24, undefined, {
    fetch: fetcher,
  });
  assert.equal(result.findings[0]?.vulnerability?.reachability, 'referenced');
  assert.ok(result.findings[0]?.evidence.some((item) => item.file === 'src/runtime.ts'));
  assert.match(result.findings[0]?.description ?? '', /vulnerable code path was not proven/);
});

test('offline advisory coverage stays partial when the local database lacks packages', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-osv-partial-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const source = snapshot({
    'package.json': '{"dependencies":{"alpha":"1.0.0","beta":"2.0.0"}}',
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { alpha: '1.0.0', beta: '2.0.0' } },
        'node_modules/alpha': { version: '1.0.0' },
        'node_modules/beta': { version: '2.0.0' },
      },
    }),
  });
  const database = path.join(directory, 'database.json');
  const fetcher: typeof fetch = async (input, init) => {
    if (String(input).endsWith('/querybatch')) {
      const body = JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] };
      return Response.json({
        results: body.queries.map((query) =>
          query.package.name === 'alpha' ? {} : { vulns: [{ id: 'GHSA-beta' }] },
        ),
      });
    }
    return Response.json({
      id: 'GHSA-beta',
      affected: [{ package: { name: 'beta' }, ranges: [] }],
    });
  };
  await scanOsv(source, true, database, 24, undefined, { fetch: fetcher });

  const changed = snapshot({
    ...Object.fromEntries(source.files.map((file) => [file.path, file.content])),
    'package.json': '{"dependencies":{"alpha":"1.0.0","beta":"2.0.0","gamma":"3.0.0"}}',
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { alpha: '1.0.0', beta: '2.0.0', gamma: '3.0.0' } },
        'node_modules/alpha': { version: '1.0.0' },
        'node_modules/beta': { version: '2.0.0' },
        'node_modules/gamma': { version: '3.0.0' },
      },
    }),
  });
  const offline = await scanOsv(changed, false, database, 24);
  assert.equal(offline.run.status, 'partial');
  assert.match(offline.run.detail, /remain unverified/);
});

test('OSV clean and malformed responses remain distinct', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-osv-clean-'));
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
  const directory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-osv-pages-'));
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
