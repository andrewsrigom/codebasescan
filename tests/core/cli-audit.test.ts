import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

test('advisory policy output separates detected candidates from gated findings', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-cli-audit-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const repository = path.resolve('.');
  const result = spawnSync(
    process.execPath,
    [
      '--experimental-strip-types',
      path.join(repository, 'src/cli/main.ts'),
      'audit',
      path.join(repository, 'fixtures/review-worthy-saas'),
      '--report-dir',
      path.join(temporary, 'report'),
      '--policy',
      'advisory',
      '--non-interactive',
      '--quiet',
    ],
    {
      cwd: temporary,
      encoding: 'utf8',
      env: {
        ...process.env,
        CODEBASESCAN_SEMGREP: 'false',
        CODEBASESCAN_GITLEAKS: 'false',
      },
    },
  );
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(
    result.stderr,
    /Policy advisory: advisory; [1-9]\d* finding candidates; 0 gated findings; 0 blocking coverage issues\./,
  );
});
