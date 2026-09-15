import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { writeStaticReport } from '../../src/reporting/static-report.ts';
import { sampleReport } from '../helpers.ts';

const execute = promisify(execFile);
const cli = path.resolve('src/cli/main.ts');

async function run(...arguments_: string[]) {
  return execute(process.execPath, [cli, ...arguments_], { timeout: 30_000 });
}

test('report commands read bounded findings and coverage by stable ID', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-inspect-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const report = sampleReport();
  const output = await writeStaticReport(report, temporary);

  const verified = await run('report', 'verify', output.directory, '--json');
  assert.equal(JSON.parse(verified.stdout).auditId, report.auditId);

  const list = await run('findings', 'list', output.directory, '--limit', '1', '--json');
  const candidates = JSON.parse(list.stdout) as {
    total: number;
    shown: number;
    findings: { id: string }[];
  };
  assert.equal(candidates.shown, 1);
  assert.equal(candidates.total, report.findings.length);
  assert.equal(candidates.findings[0]?.id, report.findings[0]?.id);

  const exact = await run('finding', 'show', output.directory, candidates.findings[0]!.id);
  assert.match(exact.stdout, /Static evidence is a review candidate/);
  assert.match(exact.stdout, /Evidence/);

  const coverage = await run('coverage', 'show', output.directory, '--json');
  assert.equal(JSON.parse(coverage.stdout).auditId, report.auditId);

  await assert.rejects(() => run('findings', 'list', output.directory, '--limit', '101'), /limit/);
  await assert.rejects(
    () => run('finding', 'show', output.directory, 'missing'),
    /Finding not found/,
  );
});

test('report commands fail closed when a managed artifact changes', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-inspect-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const output = await writeStaticReport(sampleReport(), temporary);
  const file = path.join(output.directory, 'audit-report.json');
  await writeFile(file, `${await readFile(file, 'utf8')} `);
  await assert.rejects(() => run('report', 'verify', output.directory), /integrity validation/);
  await assert.rejects(() => run('findings', 'list', output.directory), /integrity validation/);
});
