import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { buildRunManifest } from '../../src/domain/run-manifest.ts';
import { parseRunManifest } from '../../src/domain/run-manifest-schema.ts';
import { codebasescanVersion } from '../../src/domain/versions.ts';
import { sampleReport } from '../helpers.ts';

test('run manifest keeps execution, coverage, and artifact integrity explicit', () => {
  const report = sampleReport();
  report.auditModes = [
    { id: 'security', version: 'fixture-pack', enabled: true },
    { id: 'saas', version: 'fixture-pack', enabled: false },
  ];
  report.coverage = [
    { id: 'source', label: 'Source', status: 'COMPLETE', detail: 'Captured.' },
    { id: 'runtime', label: 'Runtime', status: 'NOT PERFORMED', detail: 'Not requested.' },
  ];
  report.truncated = true;
  report.skipped = { 'file-count-limit': 2 };
  const scanner = report.scanners[0];
  assert.ok(scanner);
  scanner.cache = {
    status: 'hit',
    key: 'b'.repeat(64),
    storedAt: '2026-09-10T12:00:00.000Z',
    sourceDurationMs: 25,
  };

  const manifest = parseRunManifest(
    buildRunManifest(report, [
      {
        path: 'audit-report.json',
        mediaType: 'application/json',
        bytes: 42,
        sha256: 'a'.repeat(64),
      },
    ]),
  );

  assert.deepEqual(manifest.modes.requested, ['security']);
  assert.equal(manifest.modes.selectionAvailable, true);
  assert.equal(manifest.execution.scannerStatus.completed, 1);
  assert.deepEqual(manifest.execution.cache, { eligible: 1, hits: 1, misses: 0 });
  assert.equal(manifest.coverage.status.COMPLETE, 1);
  assert.equal(manifest.coverage.status['NOT PERFORMED'], 1);
  assert.equal(manifest.scope.truncated, true);
  assert.equal(manifest.scope.skipped['file-count-limit'], 2);
  assert.equal(manifest.outputs[0]?.sha256, 'a'.repeat(64));
});

test('run manifest rejects traversal-shaped output paths', () => {
  const report = sampleReport();
  const manifest = buildRunManifest(report, [
    {
      path: '../audit-report.json',
      mediaType: 'application/json',
      bytes: 42,
      sha256: 'a'.repeat(64),
    },
  ]);
  assert.throws(() => parseRunManifest(manifest));
});

test('declared CodebaseScan version matches the package', async () => {
  const packageJson = JSON.parse(await readFile('package.json', 'utf8')) as { version?: string };
  assert.equal(codebasescanVersion, packageJson.version);
});
