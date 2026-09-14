import test from 'node:test';
import assert from 'node:assert/strict';
import {
  addCalibrationMiss,
  buildCalibrationReport,
  buildV1CalibrationGate,
  updateCalibrationScope,
  upsertCalibrationEntry,
} from '../../src/domain/calibration.ts';
import {
  calibrationLedgerJsonSchema,
  calibrationReportJsonSchema,
  parseCalibrationLedger,
  parseCalibrationReport,
  parseV1CalibrationGate,
  v1CalibrationGateJsonSchema,
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
  assert.equal(result.summary.criticalHighSamplePrecision, 1);
  assert.equal(result.summary.reviewedRecall, 1);
  assert.equal(result.summary.accuracyClaimReady, true);
  assert.equal(result.projects[0]?.label, 'P01');
  assert.ok(!JSON.stringify(result).includes(report.projectName));
});

test('v1 calibration gate exposes measured failures without overstating release readiness', () => {
  const report = sampleReport();
  let ledger = upsertCalibrationEntry(undefined, report, {
    findingId: report.findings[0]!.id,
    outcome: 'true_positive',
    evidenceAccuracy: 'correct',
    locationAccuracy: 'correct',
    explanationQuality: 'clear',
    note: 'Independent source review confirmed this candidate.',
    reviewer: 'reviewer-a',
    reviewedAt: '2026-09-11T12:00:00.000Z',
  });
  ledger = updateCalibrationScope(ledger, report, {
    candidateReview: 'complete',
    falseNegativeReview: 'sampled',
    note: 'Candidates were complete and source paths were sampled.',
    reviewer: 'reviewer-a',
    reviewedAt: '2026-09-11T12:05:00.000Z',
  });
  const calibration = buildCalibrationReport([{ report, ledger }], '2026-09-11T13:00:00.000Z');
  const gate = parseV1CalibrationGate(buildV1CalibrationGate(calibration));
  assert.equal(gate.status, 'fail');
  assert.equal(gate.checks.find((check) => check.id === 'sample-precision')?.status, 'pass');
  assert.equal(gate.checks.find((check) => check.id === 'repositories')?.actual, 1);
  assert.match(gate.limitations[0]!, /calibration subset/);
  assert.equal((v1CalibrationGateJsonSchema() as { type?: string }).type, 'object');
});

test('v1 calibration gate passes only when every measured threshold passes', () => {
  const report = sampleReport();
  const base = buildCalibrationReport([{ report }], '2026-09-11T13:00:00.000Z');
  const calibration = parseCalibrationReport({
    ...base,
    summary: {
      ...base.summary,
      projects: 10,
      reviewedCandidates: 200,
      unreviewedCandidates: 0,
      evidenceAccuracy: { correct: 194, incorrect: 4, uncertain: 2 },
      locationAccuracy: { correct: 196, incorrect: 3, uncertain: 1 },
      samplePrecision: 0.9,
      criticalHighSamplePrecision: 0.95,
    },
    projects: Array.from({ length: 10 }, (_, index) => ({
      ...base.projects[0]!,
      label: `P${String(index + 1).padStart(2, '0')}`,
      falseNegativeReview: index < 3 ? 'complete' : 'sampled',
    })),
  });
  const gate = buildV1CalibrationGate(calibration);
  assert.equal(gate.status, 'pass');
  assert.ok(gate.checks.every((check) => check.status === 'pass'));
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
