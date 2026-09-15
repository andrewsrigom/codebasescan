import test from 'node:test';
import assert from 'node:assert/strict';
import { assertPrivateSidecarDestination } from '../../src/security/private-sidecar-path.ts';

test('Windows refuses private sidecars written through WSL UNC paths', () => {
  for (const destination of [
    String.raw`\\wsl.localhost\Ubuntu-20.04\home\user\triage.json`,
    String.raw`\\WSL$\Ubuntu-20.04\home\user\review.json`,
  ])
    assert.throws(
      () => assertPrivateSidecarDestination(destination, 'win32'),
      /Run CodebaseScan inside WSL/,
    );
  assert.doesNotThrow(() =>
    assertPrivateSidecarDestination(String.raw`C:\Users\user\triage.json`, 'win32'),
  );
  assert.doesNotThrow(() =>
    assertPrivateSidecarDestination(String.raw`\\wsl.localhost\Ubuntu\triage.json`, 'linux'),
  );
});
