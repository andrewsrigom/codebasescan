import test from 'node:test';
import assert from 'node:assert/strict';
import {
  declarativeKnipConfiguration,
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
      "compilers": { ".ts": "throw new Error('must not run')" },
      "workspaces": { "tools/*": { "project": ["src/**/*.ts"] }, "../bad": {} },
    }`,
  });

  const result = declarativeKnipConfiguration(snapshot);
  assert.deepEqual(result.sources, ['knip.jsonc']);
  assert.deepEqual(result.config.entry, ['src/app/page.tsx']);
  assert.deepEqual(result.config.ignoreDependencies, ['@svgr/webpack']);
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
  });
  const result = typeScriptPathAliases(snapshot);
  assert.deepEqual(result.aliases, [
    { configFile: 'tsconfig.json', pattern: '#lib/*', targets: ['src/lib/*'] },
  ]);
  assert.equal(result.issues.length, 1);
});
