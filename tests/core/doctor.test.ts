import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeAdvisoryDatabase, supportedNodeVersion } from '../../src/cli/doctor.ts';

test('doctor enforces the declared Node.js runtime floor', () => {
  assert.equal(supportedNodeVersion('v22.16.0'), true);
  assert.equal(supportedNodeVersion('24.1.0'), true);
  assert.equal(supportedNodeVersion('v22.15.9'), false);
  assert.equal(supportedNodeVersion('not-a-version'), false);
});

test('doctor summarizes only a valid bounded advisory cache shape', () => {
  assert.deepEqual(
    summarizeAdvisoryDatabase({
      schemaVersion: 1,
      entries: {
        'npm:example:1.0.0': {
          fetchedAt: '2026-09-09T12:00:00.000Z',
          vulnerabilities: [],
        },
      },
    }),
    { packages: 1, latestFetch: '2026-09-09T12:00:00.000Z' },
  );
  assert.equal(summarizeAdvisoryDatabase({ schemaVersion: 2, entries: {} }), null);
});
