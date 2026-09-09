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
import { snapshotFromFiles } from '../helpers.ts';

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
  assert.deepEqual(
    new Set(result.hotspots.map((hotspot) => hotspot.name)),
    new Set(['complex', 'wide']),
  );
  assert.equal(result.hotspots.find((hotspot) => hotspot.name === 'complex')?.complexity, 16);
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
  assert.deepEqual(analysis.unusedDependencies, ['alpha']);
  assert.deepEqual(analysis.unusedExports, [{ file: 'src/unused.ts', line: 1, name: 'unused' }]);
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
  assert.equal(analysis.truncated, true);
});

test('dead-code scan disables target configuration loaders', async () => {
  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'traceward-quality-test-'));
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
  const temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), 'traceward-quality-config-'));
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({ dependencies: { ignored: '1.0.0' } }),
    'knip.json': JSON.stringify({
      entry: ['src/app/page.tsx'],
      project: ['src/**/*.{ts,tsx}'],
      ignoreFiles: ['src/intentionally-unused.ts'],
      ignoreDependencies: ['ignored'],
    }),
    'src/app/page.tsx': `export default function Page() { return <main>ok</main>; }`,
    'src/intentionally-unused.ts': `export const fixture = true;`,
  });
  try {
    const result = await scanCodeQuality(snapshot, undefined, temporaryDirectory);
    const knip = result.runs.find((run) => run.id === 'knip');
    assert.notEqual(knip?.status, 'failed', knip?.detail);
    assert.ok(knip?.detail.includes('knip.json'));
    assert.ok(!result.analysis.deadCode?.unusedFiles.includes('src/intentionally-unused.ts'));
    assert.ok(!result.analysis.deadCode?.unusedDependencies.includes('ignored'));
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});
