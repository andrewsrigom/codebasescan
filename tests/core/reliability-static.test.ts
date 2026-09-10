import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanReliabilityStatic } from '../../src/scanners/reliability-static.ts';
import { snapshotOf } from '../helpers.ts';

test('reliability rules find direct unbounded requests and empty catch blocks', () => {
  const snapshot = snapshotOf(
    `export async function POST() {
      try { return await fetch('https://service.example/data'); } catch {}
    }`,
    'src/app/api/sync/route.ts',
  );
  const result = scanReliabilityStatic(snapshot, profileProject(snapshot).profile);
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'TW-REL001',
    'TW-REL002',
  ]);
});

test('bounded outbound calls and explicit failure handling avoid reliability candidates', () => {
  const snapshot = snapshotOf(
    `export async function POST() {
      try {
        return await fetch('https://service.example/data', { signal: AbortSignal.timeout(5000) });
      } catch (error) { throw new Error('Sync failed', { cause: error }); }
    }`,
    'src/app/api/sync/route.ts',
  );
  const result = scanReliabilityStatic(snapshot, profileProject(snapshot).profile);
  assert.deepEqual(result.findings, []);
});
