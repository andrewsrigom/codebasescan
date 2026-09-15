import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { writeStaticReport } from '../../src/reporting/static-report.ts';
import { parseTriageLedger } from '../../src/domain/triage-ledger-schema.ts';
import { parseReviewLedger } from '../../src/domain/review-ledger-schema.ts';
import { sampleReport } from '../helpers.ts';

const execute = promisify(execFile);
const cli = path.resolve('src/cli/main.ts');

async function run(...arguments_: string[]) {
  return execute(process.execPath, ['--experimental-strip-types', cli, ...arguments_], {
    timeout: 30_000,
  });
}

test('CLI retains agent triage beside a report without changing review or policy', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-triage-cli-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const report = sampleReport();
  const output = await writeStaticReport(report, path.join(temporary, 'codebasescan-report'));
  const finding = report.findings[0]!;

  const absent = await run('triage', 'list', output.directory, '--json');
  assert.equal(JSON.parse(absent.stdout).status, 'not_recorded');

  await run(
    'triage',
    'record',
    output.directory,
    finding.id,
    'likely_false_positive',
    '--evidence',
    finding.evidence[0]!.id,
    '--note',
    'The test fixture uses a deliberately inert input.',
  );
  const ledgerPath = path.join(temporary, 'codebasescan-report.triage-ledger.json');
  const ledger = parseTriageLedger(JSON.parse(await readFile(ledgerPath, 'utf8')) as unknown);
  assert.equal(ledger.entries[0]?.assessment, 'likely_false_positive');
  await assert.rejects(() => stat(path.join(output.directory, 'triage-ledger.json')), {
    code: 'ENOENT',
  });

  const listed = await run('triage', 'list', output.directory, '--json');
  const result = JSON.parse(listed.stdout) as {
    counts: { current: number; stale: number; unmatched: number };
  };
  assert.deepEqual(result.counts, { current: 1, stale: 0, unmatched: 0 });
  const unchanged = JSON.parse(
    await readFile(path.join(output.directory, 'audit-report.json'), 'utf8'),
  ) as {
    findings: { disposition: string }[];
  };
  assert.equal(unchanged.findings[0]?.disposition, 'needs_review');

  await run(
    'review',
    output.directory,
    finding.id,
    'false_positive',
    '--note',
    'An independent reviewer verified the inert test fixture.',
  );
  const reviewPath = path.join(temporary, 'codebasescan-report.review-ledger.json');
  const review = parseReviewLedger(JSON.parse(await readFile(reviewPath, 'utf8')) as unknown);
  assert.equal(review.entries[0]?.decision, 'false_positive');
  await assert.rejects(() => stat(path.join(output.directory, 'review-ledger.json')), {
    code: 'ENOENT',
  });
});
