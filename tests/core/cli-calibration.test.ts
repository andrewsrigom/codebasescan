import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import {
  parseCalibrationLedger,
  parseCalibrationReport,
} from '../../src/domain/calibration-schema.ts';
import { sampleReport } from '../helpers.ts';

function runCli(cwd: string, arguments_: string[]) {
  const result = spawnSync(
    process.execPath,
    ['--experimental-strip-types', path.resolve('src/cli/main.ts'), ...arguments_],
    { cwd, encoding: 'utf8', env: process.env },
  );
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  return result;
}

test('CLI records calibration beside an immutable report and evaluates artifacts', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-calibration-cli-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const reportDirectory = path.join(temporary, 'audit-one');
  await mkdir(reportDirectory);
  const report = sampleReport();
  report.projectName = 'private-calibration-project';
  await writeFile(
    path.join(reportDirectory, 'audit-report.json'),
    `${JSON.stringify(report, null, 2)}\n`,
  );

  runCli(temporary, [
    'calibration',
    'review',
    reportDirectory,
    report.findings[0]!.id,
    'true_positive',
    '--reviewer',
    'owner-reviewer',
    '--note',
    'Independent source review confirmed this candidate.',
    '--evidence',
    'correct',
    '--location',
    'correct',
    '--explanation',
    'clear',
  ]);
  runCli(temporary, [
    'calibration',
    'scope',
    reportDirectory,
    '--candidates',
    'complete',
    '--false-negatives',
    'complete',
    '--reviewer',
    'owner-reviewer',
    '--note',
    'All supported candidates and source paths were reviewed.',
  ]);

  const ledgerPath = path.join(temporary, 'audit-one.calibration.json');
  const ledger = parseCalibrationLedger(JSON.parse(await readFile(ledgerPath, 'utf8')) as unknown);
  assert.equal(ledger.entries[0]?.outcome, 'true_positive');
  assert.equal(ledger.reviewScope?.candidateReview, 'complete');

  const output = path.join(temporary, 'calibration-report.json');
  runCli(temporary, ['evaluate', reportDirectory, '--artifacts', '--output', output]);
  const evaluation = parseCalibrationReport(JSON.parse(await readFile(output, 'utf8')) as unknown);
  assert.equal(evaluation.summary.accuracyClaimReady, true);
  assert.equal(evaluation.summary.samplePrecision, 1);
  assert.ok(!JSON.stringify(evaluation).includes(report.projectName));
});
