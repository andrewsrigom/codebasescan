import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { scanExternal } from '../../src/scanners/external.ts';
import { snapshotOf } from '../helpers.ts';

const hasSemgrep = spawnSync('semgrep', ['--version'], { stdio: 'ignore' }).status === 0;
const hasGitleaks = spawnSync('gitleaks', ['version'], { stdio: 'ignore' }).status === 0;

test(
  'installed Semgrep runs through the isolated adapter',
  { skip: !hasSemgrep },
  async (context) => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-semgrep-test-'));
    context.after(() => rm(temporary, { recursive: true, force: true }));
    const result = await scanExternal(
      'semgrep',
      snapshotOf('eval(input)'),
      true,
      temporary,
      path.resolve('configs'),
    );
    assert.ok(['completed', 'partial'].includes(result.run.status));
    assert.match(result.run.version ?? '', /^\d+\.\d+\.\d+$/);
    assert.ok(result.findings.some((finding) => finding.source === 'semgrep'));
  },
);

test(
  'installed Gitleaks runs through the isolated adapter',
  { skip: !hasGitleaks },
  async (context) => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-gitleaks-test-'));
    context.after(() => rm(temporary, { recursive: true, force: true }));
    const result = await scanExternal(
      'gitleaks',
      snapshotOf("const token = 'ghp_000000000000000000000000000000000000';"),
      true,
      temporary,
      path.resolve('configs'),
    );
    assert.ok(['completed', 'partial'].includes(result.run.status));
    assert.match(result.run.version ?? '', /^\d+\.\d+\.\d+$/);
    assert.ok(!JSON.stringify(result).includes('ghp_000000000000000000000000000000000000'));
  },
);
