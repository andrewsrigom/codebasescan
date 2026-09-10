import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  coverageArtifacts,
  measureCodeQuality,
  normalizeKnip,
  scanCodeQuality,
} from '../../src/scanners/quality.ts';
import { snapshotFromFiles, snapshotOf } from '../helpers.ts';

test('quality metrics retain only oversized, complex, or wide functions', () => {
  const branches = Array.from(
    { length: 15 },
    (_, index) => `if (value === ${index}) value++;`,
  ).join('\n');
  const snapshot = snapshotFromFiles({
    'src/quality.ts': `
      export function simple(value: number) { return value + 1; }
      export function complex(value: number) {
        ${branches}
        return value;
      }
      export const wide = (a: number, b: number, c: number, d: number, e: number, f: number) => a + b + c + d + e + f;
    `,
  });

  const result = measureCodeQuality(snapshot);
  assert.equal(result.functionsAnalyzed, 3);
  assert.equal(result.hotspotCount, 2);
  assert.deepEqual(
    new Set(result.hotspots.map((hotspot) => hotspot.name)),
    new Set(['complex', 'wide']),
  );
  assert.equal(result.hotspots.find((hotspot) => hotspot.name === 'complex')?.complexity, 16);
});

test('quality metrics keep an exact hotspot total when detail rows are bounded', () => {
  const branches = Array.from(
    { length: 15 },
    (_, index) => `if (value === ${index}) value++;`,
  ).join('\n');
  const functions = Array.from(
    { length: 205 },
    (_, index) => `export function hotspot${index}(value: number) { ${branches} return value; }`,
  ).join('\n');

  const result = measureCodeQuality(snapshotOf(functions));

  assert.equal(result.hotspotCount, 205);
  assert.equal(result.hotspots.length, 200);
  assert.equal(result.truncated, true);
});

test('coverage artifacts import summary percentages without source coverage payloads', () => {
  const snapshot = snapshotFromFiles({
    'coverage/coverage-summary.json': JSON.stringify({
      total: {
        lines: { total: 10, covered: 8, pct: 80 },
        statements: { total: 10, covered: 7, pct: 70 },
        functions: { total: 4, covered: 2, pct: 50 },
        branches: { total: 8, covered: 2, pct: 25 },
      },
    }),
    'coverage/lcov.info': 'LF:10\nLH:8\nFNF:4\nFNH:2\nBRF:8\nBRH:2\nend_of_record\n',
  });

  assert.deepEqual(coverageArtifacts(snapshot), [
    {
      file: 'coverage/coverage-summary.json',
      lines: 80,
      statements: 70,
      functions: 50,
      branches: 25,
    },
    { file: 'coverage/lcov.info', lines: 80, functions: 50, branches: 25 },
  ]);
});

test('Knip JSON normalization bounds paths and dead-code symbols', () => {
  const snapshot = snapshotFromFiles({
    'package.json': '{}',
    'src/unused.ts': 'export const unused = true;',
  });
  const analysis = normalizeKnip(
    {
      issues: [
        {
          file: 'src/unused.ts',
          files: [{ name: 'src/unused.ts' }],
          exports: [{ name: 'unused', line: 1 }],
        },
        { file: '../../outside.ts', files: [{ name: '../../outside.ts' }] },
        { file: 'package.json', dependencies: [{ name: 'alpha' }] },
      ],
    },
    snapshot,
  );
  assert.deepEqual(analysis.unusedFiles, ['src/unused.ts']);
  assert.equal(analysis.unusedFileCount, 1);
  assert.deepEqual(analysis.unusedDependencies, ['alpha']);
  assert.equal(analysis.unusedDependencyCount, 1);
  assert.deepEqual(analysis.unusedExports, [{ file: 'src/unused.ts', line: 1, name: 'unused' }]);
  assert.equal(analysis.unusedExportCount, 1);
  assert.ok(!JSON.stringify(analysis).includes('outside'));
});

test('Knip normalization marks individually bounded result categories as partial', () => {
  const files = Object.fromEntries(
    Array.from({ length: 301 }, (_, index) => [`src/unused-${index}.ts`, 'export {};']),
  );
  const snapshot = snapshotFromFiles(files);
  const analysis = normalizeKnip(
    {
      issues: Object.keys(files).map((file) => ({ file, files: [{ name: file }] })),
    },
    snapshot,
  );

  assert.equal(analysis.unusedFiles.length, 300);
  assert.equal(analysis.unusedFileCount, 301);
  assert.equal(analysis.truncated, true);
});

test('dead-code scan disables target configuration loaders', async () => {
  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-quality-test-'));
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({ dependencies: { next: '16.3.4', unused: '1.0.0' } }),
    'src/app/page.tsx': `import { used } from './used'; export default function Page() { return <main>{used}</main>; }`,
    'src/app/used.ts': `export const used = 'used'; export const notUsed = 'unused';`,
    'next.config.ts': `throw new Error('target configuration must not execute');`,
  });
  try {
    const result = await scanCodeQuality(snapshot, undefined, temporaryDirectory);
    const knip = result.runs.find((run) => run.id === 'knip');
    assert.notEqual(knip?.status, 'failed', knip?.detail);
    assert.ok(result.analysis.deadCode);
    assert.ok(
      result.analysis.deadCode.unusedDependencies.includes('unused'),
      JSON.stringify(result.analysis.deadCode),
    );
    assert.ok(
      result.analysis.deadCode.unusedExports.some(
        (item) => item.file === 'src/app/used.ts' && item.name === 'notUsed',
      ),
    );
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});

test('dead-code scan applies safe declarative Knip exclusions', async () => {
  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-quality-config-'));
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({
      dependencies: {
        ignored: '1.0.0',
        used: '1.0.0',
        tsx: '1.0.0',
        '@tailwindcss/postcss': '1.0.0',
      },
      scripts: { task: 'tsx scripts/task.ts' },
      workspaces: ['apps/*'],
    }),
    'apps/example/package.json': JSON.stringify({ name: 'example', private: true }),
    'tsconfig.json': JSON.stringify({
      compilerOptions: { paths: { '@/*': ['./src/*'] } },
    }),
    'knip.json': JSON.stringify({
      entry: ['src/app/page.tsx'],
      project: ['src/**/*.{ts,tsx}'],
      ignoreFiles: ['src/intentionally-unused.ts'],
      ignoreDependencies: ['ignored'],
    }),
    'src/app/page.tsx': `import value from 'used'; import { component } from '@/component'; export default function Page() { return <main>{value}{component}</main>; }`,
    'src/component.ts': `export const component = 'component';`,
    'src/tested.ts': `export const testedOnly = 'tested';`,
    '__tests__/tested.test.ts': `import { testedOnly } from '../src/tested'; void testedOnly;`,
    'src/intentionally-unused.ts': `export const fixture = true;`,
    'scripts/task.ts': `export const task = true;`,
    'postcss.config.mjs': `export default { plugins: { '@tailwindcss/postcss': {} } };`,
  });
  snapshot.files.find((file) => file.path === '__tests__/tested.test.ts')!.scope = 'test';
  try {
    const result = await scanCodeQuality(snapshot, undefined, temporaryDirectory);
    const knip = result.runs.find((run) => run.id === 'knip');
    assert.notEqual(knip?.status, 'failed', knip?.detail);
    assert.ok(knip?.detail.includes('knip.json'));
    assert.ok(!result.analysis.deadCode?.unusedFiles.includes('src/intentionally-unused.ts'));
    assert.ok(!result.analysis.deadCode?.unusedFiles.includes('src/component.ts'));
    assert.ok(!result.analysis.deadCode?.unusedFiles.includes('__tests__/tested.test.ts'));
    assert.ok(
      !result.analysis.deadCode?.unusedExports.some(
        (item) => item.file === 'src/tested.ts' && item.name === 'testedOnly',
      ),
    );
    assert.ok(!result.analysis.deadCode?.unusedFiles.includes('scripts/task.ts'));
    assert.ok(!result.analysis.deadCode?.unusedFiles.includes('postcss.config.mjs'));
    assert.ok(!result.analysis.deadCode?.unusedDependencies.includes('ignored'));
    assert.ok(!result.analysis.deadCode?.unusedDependencies.includes('used'));
    assert.ok(!result.analysis.deadCode?.unusedDependencies.includes('tsx'));
    assert.ok(!result.analysis.deadCode?.unusedDependencies.includes('@tailwindcss/postcss'));
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});
