import test from 'node:test';
import assert from 'node:assert/strict';
import {
  declarativeKnipConfiguration,
  declarativeSaasConfiguration,
  declarativeWorkspacePatterns,
  sanitizedManifest,
  typeScriptPathAliases,
} from '../../src/scanners/declarative-config.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('declarative Knip JSONC is sanitized without running target code', () => {
  const snapshot = snapshotFromFiles({
    'knip.jsonc': `{
      // Only bounded declarative fields are accepted.
      "entry": ["src/app/page.tsx", "../outside.ts"],
      "ignoreDependencies": ["@svgr/webpack", "../outside"],
      "paths": { "@/*": ["src/*"], "bad": ["../outside/*"] },
      "compilers": { ".ts": "throw new Error('must not run')" },
      "workspaces": { "tools/*": { "project": ["src/**/*.ts"] }, "../bad": {} },
    }`,
  });

  const result = declarativeKnipConfiguration(snapshot);
  assert.deepEqual(result.sources, ['knip.jsonc']);
  assert.deepEqual(result.config.entry, ['src/app/page.tsx']);
  assert.deepEqual(result.config.ignoreDependencies, ['@svgr/webpack']);
  assert.deepEqual(result.config.paths, { '@/*': ['src/*'] });
  assert.deepEqual(Object.keys(result.config.workspaces as object), ['tools/*']);
  assert.equal(result.config.compilers, undefined);
  assert.equal(result.issues.length, 1);
});

test('executable Knip configuration is detected but never imported', () => {
  const snapshot = snapshotFromFiles({
    'knip.config.ts': `throw new Error('must not run'); export default {};`,
  });
  const result = declarativeKnipConfiguration(snapshot);
  assert.deepEqual(result.config, {});
  assert.ok(result.issues[0]?.includes('Executable Knip configuration'));
});

test('declarative SaaS configuration extends bounded generic semantics', () => {
  const snapshot = snapshotFromFiles({
    'traceward.config.jsonc': `{
      // Project terms extend the generic defaults.
      "schemaVersion": 1,
      "vocabulary": {
        "tenantKeys": ["customerWorkspaceKey"],
        "roleKeys": ["membershipLevel"]
      },
      "helpers": {
        "authorization": ["requireMembership"],
        "resourceScope": ["scopeToCustomerWorkspace"]
      },
      "expectedUnauthenticatedRoutes": ["/api/health", "/api/public/*"]
    }`,
  });

  const result = declarativeSaasConfiguration(snapshot);
  assert.deepEqual(result.sources, ['traceward.config.jsonc']);
  assert.ok(result.config.vocabulary.tenantKeys.includes('tenantId'));
  assert.ok(result.config.vocabulary.tenantKeys.includes('customerWorkspaceKey'));
  assert.ok(result.config.helpers.authorization.includes('requireMembership'));
  assert.deepEqual(result.config.expectedUnauthenticatedRoutes, ['/api/health', '/api/public/*']);
  assert.deepEqual(result.issues, []);
});

test('unsafe SaaS settings are reported and removed without executing code', () => {
  const snapshot = snapshotFromFiles({
    'traceward.config.json': JSON.stringify({
      schemaVersion: 1,
      vocabulary: { tenantKeys: ['workspaceId', 'bad.name'] },
      helpers: { authorization: ['requireRole'], execute: ['targetCode'] },
      expectedUnauthenticatedRoutes: ['/api/health', '../outside', '/api/(.*)'],
      plugins: ['./target-code.ts'],
    }),
  });

  const result = declarativeSaasConfiguration(snapshot);
  assert.equal(result.issues.length, 1);
  assert.ok(result.config.vocabulary.tenantKeys.includes('workspaceId'));
  assert.ok(!result.config.vocabulary.tenantKeys.includes('bad.name'));
  assert.deepEqual(result.config.expectedUnauthenticatedRoutes, ['/api/health']);
  assert.equal((result.config.helpers as unknown as Record<string, unknown>).execute, undefined);
});

test('executable Traceward configuration is detected but never imported', () => {
  const snapshot = snapshotFromFiles({
    'traceward.config.ts': `throw new Error('must not run'); export default {};`,
  });
  const result = declarativeSaasConfiguration(snapshot);
  assert.deepEqual(result.sources, []);
  assert.ok(result.issues[0]?.includes('Executable Traceward configuration'));
});

test('workspace manifests and pnpm declarations are read as data', () => {
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({ workspaces: ['apps/*'] }),
    'pnpm-workspace.yaml': `packages:\n  - tools/*\n  - ../outside\n`,
  });
  assert.deepEqual(declarativeWorkspacePatterns(snapshot), ['apps/*', 'tools/*']);
});

test('staged manifests keep dependency metadata but drop scripts', () => {
  const file = snapshotFromFiles({
    'package.json': JSON.stringify({
      name: 'sample',
      scripts: { scan: 'node ../../outside.js' },
      dependencies: { next: '16.0.0' },
    }),
  }).files[0]!;
  const manifest = sanitizedManifest(file, ['apps/*']);
  assert.deepEqual(manifest.dependencies, { next: '16.0.0' });
  assert.deepEqual(manifest.workspaces, ['apps/*']);
  assert.equal(manifest.scripts, undefined);
});

test('TypeScript aliases accept JSONC and cannot escape the captured project', () => {
  const snapshot = snapshotFromFiles({
    'tsconfig.json': `{
      "compilerOptions": {
        "baseUrl": ".",
        "paths": {
          "#lib/*": ["./src/lib/*"],
          "#outside/*": ["../shared/*"],
        },
      },
    }`,
    'apps/mock/tsconfig.json': JSON.stringify({
      compilerOptions: { paths: { '@/*': ['../../src/*'] } },
    }),
  });
  const result = typeScriptPathAliases(snapshot);
  assert.deepEqual(result.aliases, [
    { configFile: 'tsconfig.json', pattern: '#lib/*', targets: ['src/lib/*'] },
    { configFile: 'apps/mock/tsconfig.json', pattern: '@/*', targets: ['src/*'] },
  ]);
  assert.equal(result.issues.length, 1);
});
