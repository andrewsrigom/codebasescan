import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeArchitecture, normalizeDuplication } from '../../src/scanners/mechanical.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('dependency structure normalization keeps bounded local evidence', () => {
  const snapshot = snapshotFromFiles({
    'src/a.ts': "import { b } from './b'; export const a = b;",
    'src/b.ts': "import { a } from './a'; export const b = a;",
    'src/app/page.tsx': 'export default function Page() { return <main />; }',
  });
  const analysis = normalizeArchitecture(
    {
      modules: [
        {
          source: 'src/a.ts',
          orphan: false,
          instability: 0.5,
          dependents: ['src/b.ts'],
          dependencies: [
            {
              resolved: 'src/b.ts',
              circular: true,
              cycle: [{ name: 'src/b.ts' }, { name: 'src/a.ts' }],
            },
            { resolved: '../../outside.ts', circular: false },
          ],
        },
        {
          source: 'src/b.ts',
          orphan: false,
          dependents: ['src/a.ts'],
          dependencies: [{ resolved: 'src/a.ts', circular: true }],
        },
        {
          source: 'src/app/page.tsx',
          orphan: true,
          dependents: [],
          dependencies: [],
        },
      ],
      summary: { totalCruised: 3, totalDependenciesCruised: 3 },
    },
    snapshot,
  );
  assert.equal(analysis.modules, 3);
  assert.equal(analysis.localDependencies, 2);
  assert.deepEqual(analysis.cycles[0]?.files, ['src/a.ts', 'src/b.ts']);
  assert.deepEqual(analysis.orphanCandidates, []);
  assert.equal(analysis.hotspots[0]?.incoming, 1);
  assert.ok(!JSON.stringify(analysis).includes('outside.ts'));
});

test('duplication normalization discards source fragments and unsafe paths', () => {
  const repeated = Array.from(
    { length: 20 },
    (_, index) => `export const value${index} = ${index};`,
  ).join('\n');
  const snapshot = snapshotFromFiles({
    'src/a.ts': repeated,
    'src/b.ts': repeated,
  });
  const analysis = normalizeDuplication(
    {
      statistics: {
        total: {
          clones: 2,
          duplicatedLines: 12,
          lines: 40,
          percentage: 30,
          sources: 2,
          tokens: 200,
        },
      },
      duplicates: [
        {
          firstFile: { name: 'src/a.ts', start: 1, end: 12 },
          secondFile: { name: 'src/b.ts', start: 1, end: 12 },
          fragment: 'must-not-be-retained',
          format: 'typescript',
          kind: 'exact',
          lines: 12,
          tokens: 80,
        },
        {
          firstFile: { name: '../../outside.ts', start: 1, end: 12 },
          secondFile: { name: 'src/b.ts', start: 1, end: 12 },
          fragment: 'outside-source',
          format: 'typescript',
          kind: 'exact',
          lines: 12,
          tokens: 80,
        },
      ],
    },
    snapshot,
  );
  assert.equal(analysis.blocks.length, 1);
  assert.equal(analysis.truncated, true);
  assert.equal(analysis.percentage, 30);
  assert.ok(!JSON.stringify(analysis).includes('must-not-be-retained'));
  assert.ok(!JSON.stringify(analysis).includes('outside-source'));
});

test('malformed mechanical scanner reports fail explicitly', () => {
  const snapshot = snapshotFromFiles({ 'src/a.ts': 'export const a = true;' });
  assert.throws(() => normalizeArchitecture({}, snapshot), /dependency-cruiser/);
  assert.throws(() => normalizeDuplication({}, snapshot), /jscpd/);
});
