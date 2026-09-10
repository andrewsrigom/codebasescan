import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { cleanupStaleScannerStaging } from '../../src/scanners/external.ts';

test('worker startup removes only recognized stale scanner staging', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-staging-recovery-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-staging-outside-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  context.after(() => rm(outside, { recursive: true, force: true }));

  await mkdir(path.join(temporary, 'semgrep-old', 'source'), { recursive: true });
  await writeFile(path.join(temporary, 'semgrep-old', 'source', 'secret.ts'), 'private');
  await mkdir(path.join(temporary, 'gitleaks-old'), { recursive: true });
  await writeFile(path.join(temporary, 'gitleaks-old', 'result.json'), '[]');
  await mkdir(path.join(temporary, 'keep-me'));
  await writeFile(path.join(temporary, 'keep-me', 'note.txt'), 'keep');
  await writeFile(path.join(temporary, 'semgrep-regular-file'), 'keep');
  await writeFile(path.join(outside, 'marker.txt'), 'outside');
  await symlink(outside, path.join(temporary, 'gitleaks-link'), 'dir');

  assert.equal(await cleanupStaleScannerStaging(temporary), 3);
  await assert.rejects(lstat(path.join(temporary, 'semgrep-old')), { code: 'ENOENT' });
  await assert.rejects(lstat(path.join(temporary, 'gitleaks-old')), { code: 'ENOENT' });
  await assert.rejects(lstat(path.join(temporary, 'gitleaks-link')), { code: 'ENOENT' });
  assert.equal(await readFile(path.join(outside, 'marker.txt'), 'utf8'), 'outside');
  assert.equal(await readFile(path.join(temporary, 'keep-me', 'note.txt'), 'utf8'), 'keep');
  assert.equal(await readFile(path.join(temporary, 'semgrep-regular-file'), 'utf8'), 'keep');
});
