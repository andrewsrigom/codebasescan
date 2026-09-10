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
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-semgrep-test-'));
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
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-gitleaks-history-test-'));
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
    git('config', 'user.email', 'codebasescan@example.invalid');
    git('config', 'user.name', 'CodebaseScan test');
    await writeFile(
      path.join(rules, 'gitleaks.toml'),
      `title = "CodebaseScan history integration fixture"\n[[rules]]\nid = "history-fixture"\ndescription = "History fixture"\nregex = '''codebasescan-secret-[A-Za-z0-9]{20}'''\n`,
    );
    const secret = ['codebasescan', 'secret', '1234567890' + 'abcdefghij'].join('-');
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
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-gitleaks-test-'));
    context.after(() => rm(temporary, { recursive: true, force: true }));
    const result = await scanExternal(
      'gitleaks',
      snapshotOf(`const token = '${['ghp', '0'.repeat(36)].join('_')}';`),
      true,
      temporary,
      path.resolve('configs'),
    );
    assert.ok(['completed', 'partial'].includes(result.run.status));
    assert.match(result.run.version ?? '', /^\d+\.\d+\.\d+$/);
    assert.ok(!JSON.stringify(result).includes(['ghp', '0'.repeat(36)].join('_')));
  },
);
