import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, unlink, writeFile } from 'node:fs/promises';
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
  'installed Gitleaks scans explicitly approved Git history without retaining values',
  { skip: !hasGitleaks },
  async (context) => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-gitleaks-history-test-'));
    const project = path.join(temporary, 'project');
    const staging = path.join(temporary, 'staging');
    const rules = path.join(temporary, 'rules');
    await mkdir(project);
    await mkdir(rules);
    context.after(() => rm(temporary, { recursive: true, force: true }));
    const git = (...args: string[]) => {
      const result = spawnSync('git', args, { cwd: project, encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
    };
    git('init', '--quiet');
    git('config', 'user.email', 'traceward@example.invalid');
    git('config', 'user.name', 'Traceward test');
    await writeFile(
      path.join(rules, 'gitleaks.toml'),
      `title = "Traceward history integration fixture"\n[[rules]]\nid = "history-fixture"\ndescription = "History fixture"\nregex = '''traceward-secret-[A-Za-z0-9]{20}'''\n`,
    );
    const secret = 'traceward-secret-1234567890abcdefghij';
    await writeFile(path.join(project, 'removed.ts'), `export const token = '${secret}';\n`);
    git('add', 'removed.ts');
    git('commit', '--quiet', '-m', 'add fixture');
    await unlink(path.join(project, 'removed.ts'));
    git('add', '--all');
    git('commit', '--quiet', '-m', 'remove fixture');

    const result = await scanExternal(
      'gitleaks',
      snapshotOf('export const current = true;', 'current.ts'),
      true,
      staging,
      rules,
      undefined,
      { projectRoot: project, gitHistory: true },
    );
    assert.ok(['completed', 'partial'].includes(result.run.status));
    assert.ok(
      result.findings.some((finding) => finding.secret?.classification === 'historical'),
      JSON.stringify(result),
    );
    assert.ok(!JSON.stringify(result).includes(secret));
    assert.match(result.run.detail, /approved Git history/);
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
