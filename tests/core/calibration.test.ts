import test from 'node:test';
import assert from 'node:assert/strict';
import {
  addCalibrationMiss,
  buildCalibrationReport,
  updateCalibrationScope,
  upsertCalibrationEntry,
} from '../../src/domain/calibration.ts';
import {
  calibrationLedgerJsonSchema,
  calibrationReportJsonSchema,
  parseCalibrationLedger,
  parseCalibrationReport,
} from '../../src/domain/calibration-schema.ts';
import { sampleReport } from '../helpers.ts';

test('calibration keeps reviewer ground truth separate from scanner findings', () => {
  const report = sampleReport();
  report.projectName = 'private-project-identifier';
  const finding = report.findings[0]!;
  let ledger = upsertCalibrationEntry(undefined, report, {
    findingId: finding.id,
    outcome: 'true_positive',
    evidenceAccuracy: 'correct',
    locationAccuracy: 'correct',
    explanationQuality: 'clear',
    note: 'Independent review confirmed the request-controlled flow.',
    reviewer: 'reviewer-a',
    reviewedAt: '2026-09-11T12:00:00.000Z',
  });
  ledger = updateCalibrationScope(ledger, report, {
    candidateReview: 'complete',
    falseNegativeReview: 'complete',
    note: 'Every candidate and supported source path was reviewed.',
    reviewer: 'reviewer-a',
    reviewedAt: '2026-09-11T12:05:00.000Z',
  });
  const parsedLedger = parseCalibrationLedger(ledger);
  const result = parseCalibrationReport(
    buildCalibrationReport([{ report, ledger: parsedLedger }], '2026-09-11T13:00:00.000Z'),
  );
  assert.equal(report.findings[0]!.disposition, 'needs_review');
  assert.equal(result.summary.reviewedCandidates, 1);
  assert.equal(result.summary.outcomes.true_positive, 1);
  assert.equal(result.summary.samplePrecision, 1);
  assert.equal(result.summary.reviewedRecall, 1);
  assert.equal(result.summary.accuracyClaimReady, true);
  assert.equal(result.projects[0]?.label, 'P01');
  assert.ok(!JSON.stringify(result).includes(report.projectName));
});

test('calibration stays partial until candidates and false negatives are reviewed', () => {
  const report = sampleReport();
  const result = buildCalibrationReport([{ report }], '2026-09-11T13:00:00.000Z');
  assert.equal(result.summary.unreviewedCandidates, report.findings.length);
  assert.equal(result.summary.samplePrecision, undefined);
  assert.equal(result.summary.reviewedRecall, undefined);
  assert.equal(result.summary.accuracyClaimReady, false);
});

test('manual misses are bounded, relative, and included in reviewed recall', () => {
  const report = sampleReport();
  let ledger = upsertCalibrationEntry(undefined, report, {
    findingId: report.findings[0]!.id,
    outcome: 'true_positive',
    evidenceAccuracy: 'correct',
    locationAccuracy: 'correct',
    explanationQuality: 'clear',
    note: 'The scanner evidence and source location are correct.',
    reviewer: 'reviewer-a',
    reviewedAt: '2026-09-11T12:00:00.000Z',
  });
  ledger = addCalibrationMiss(ledger, report, {
    expectedRuleId: 'TW-AST999',
    file: 'src/missed.ts',
    line: 12,
    note: 'Manual review found a supported sink the scanner missed.',
    reviewer: 'reviewer-a',
    reviewedAt: '2026-09-11T12:01:00.000Z',
  });
  ledger = updateCalibrationScope(ledger, report, {
    candidateReview: 'complete',
    falseNegativeReview: 'complete',
    note: 'Complete candidate and false-negative review was performed.',
    reviewer: 'reviewer-a',
    reviewedAt: '2026-09-11T12:02:00.000Z',
  });
  const result = buildCalibrationReport([{ report, ledger }], '2026-09-11T13:00:00.000Z');
  assert.equal(result.summary.manualMisses, 1);
  assert.equal(result.summary.reviewedRecall, 0.5);
  assert.equal(result.rules.find((rule) => rule.id === 'manual:TW-AST999')?.manualMisses, 1);
  assert.throws(
    () =>
      addCalibrationMiss(ledger, report, {
        file: '../outside.ts',
        note: 'This source path leaves the audited project boundary.',
        reviewer: 'reviewer-a',
      }),
    /stay inside/,
  );
});

test('calibration rejects ledgers from a different snapshot and publishes schemas', () => {
  const report = sampleReport();
  const ledger = upsertCalibrationEntry(undefined, report, {
    findingId: report.findings[0]!.id,
    outcome: 'inconclusive',
    evidenceAccuracy: 'uncertain',
    locationAccuracy: 'uncertain',
    explanationQuality: 'uncertain',
    note: 'The available source evidence does not settle this candidate.',
    reviewer: 'reviewer-a',
  });
  const changed = structuredClone(report);
  changed.snapshotDigest = 'f'.repeat(64);
  assert.throws(() => buildCalibrationReport([{ report: changed, ledger }]), /different audit/);
  assert.equal((calibrationLedgerJsonSchema() as { type?: string }).type, 'object');
  assert.equal((calibrationReportJsonSchema() as { type?: string }).type, 'object');
});
