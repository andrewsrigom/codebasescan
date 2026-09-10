import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import type { ScannerRun } from '../../src/domain/types.ts';
import { runCachedScan, scannerCacheLimits } from '../../src/engine/scanner-cache.ts';

const snapshotDigest = 'a'.repeat(64);
const result = (findings: number): { findings: never[]; run: ScannerRun } => ({
  findings: [],
  run: {
    id: 'example',
    name: 'Example',
    status: 'completed' as const,
    durationMs: 25,
    findings,
    detail: 'Bounded deterministic example.',
    version: '1.0.0',
  },
});

test('scanner cache reuses only an exact snapshot, scanner version, and variant', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-scanner-cache-'));
  let calls = 0;
  const options = {
    snapshotDigest,
    scannerId: 'example',
    scannerVersion: '1.0.0',
    expectedRunIds: ['example'],
    variant: 'default',
  };
  const first = await runCachedScan({ directory, enabled: true }, options, () => {
    calls++;
    return result(1);
  });
  const second = await runCachedScan({ directory, enabled: true }, options, () => {
    calls++;
    return result(2);
  });
  const changed = await runCachedScan(
    { directory, enabled: true },
    { ...options, scannerVersion: '1.0.1' },
    () => {
      calls++;
      return result(3);
    },
  );

  assert.equal(calls, 2);
  assert.equal(first.run.cache?.status, 'miss');
  assert.equal(second.run.cache?.status, 'hit');
  assert.equal(second.run.findings, 1);
  assert.equal(second.run.cache?.sourceDurationMs, 25);
  assert.equal(changed.run.cache?.status, 'miss');
  assert.notEqual(changed.run.cache?.key, first.run.cache?.key);
});

test('scanner cache fails closed for malformed and oversized entries', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-scanner-cache-'));
  const options = {
    snapshotDigest,
    scannerId: 'example',
    scannerVersion: '1.0.0',
    expectedRunIds: ['example'],
  };
  const first = await runCachedScan({ directory, enabled: true }, options, () => result(1));
  const key = first.run.cache?.key;
  assert.ok(key);
  const file = path.join(directory, `${key}.json`);
  await writeFile(file, '{"schemaVersion":1,"value":{"run":{"id":"wrong"}}}\n');

  let calls = 0;
  const repaired = await runCachedScan({ directory, enabled: true }, options, () => {
    calls++;
    return result(2);
  });
  assert.equal(calls, 1);
  assert.equal(repaired.run.findings, 2);
  assert.equal(repaired.run.cache?.status, 'miss');
  assert.ok((await readFile(file)).byteLength < scannerCacheLimits.maximumEntryBytes);

  const oversized = {
    ...result(3),
    payload: 'x'.repeat(scannerCacheLimits.maximumEntryBytes),
  };
  const bounded = await runCachedScan(
    { directory, enabled: true },
    { ...options, variant: 'oversized' },
    () => oversized,
  );
  assert.equal(bounded.run.cache?.status, 'miss');
  assert.equal(bounded.run.cache?.storedAt, undefined);
});

test('disabled scanner cache performs no reuse', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-scanner-cache-'));
  let calls = 0;
  const options = {
    snapshotDigest,
    scannerId: 'example',
    scannerVersion: '1.0.0',
    expectedRunIds: ['example'],
  };
  const first = await runCachedScan({ directory, enabled: false }, options, () => {
    calls++;
    return result(1);
  });
  await runCachedScan({ directory, enabled: false }, options, () => {
    calls++;
    return result(1);
  });
  assert.equal(calls, 2);
  assert.equal(first.run.cache, undefined);
});
