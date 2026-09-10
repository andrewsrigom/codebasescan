import test from 'node:test';
import assert from 'node:assert/strict';
import { compareReports } from '../../src/domain/comparison.ts';
import { buildPolicyResult } from '../../src/domain/policy.ts';
import { parsePolicyResult } from '../../src/domain/policy-schema.ts';
import { sampleReport } from '../helpers.ts';

test('advisory records matches and coverage gaps without failing', () => {
  const report = sampleReport();
  report.coverage = [{ id: 'source', label: 'Source', status: 'FAILED', detail: 'Parser failed.' }];
  const result = parsePolicyResult(buildPolicyResult(report, 'advisory'));
  assert.equal(result.decision, 'advisory');
  assert.equal(result.exitCode, 0);
  assert.equal(result.summary.matchedFindings, 1);
  assert.equal(result.summary.blockingCoverageIssues, 0);
});

test('balanced gates medium-confidence high findings and failed coverage', () => {
  const report = sampleReport();
  report.findings[0]!.severity = 'high';
  report.findings[0]!.confidence = 'medium';
  let result = buildPolicyResult(report, 'balanced');
  assert.equal(result.exitCode, 1);
  assert.equal(result.summary.gatedFindings, 1);

  report.coverage = [{ id: 'source', label: 'Source', status: 'FAILED', detail: 'Parser failed.' }];
  result = buildPolicyResult(report, 'balanced');
  assert.equal(result.exitCode, 2);
  assert.equal(result.summary.blockingCoverageIssues, 1);
});

test('balanced baseline gates only new findings while strict includes existing debt', () => {
  const base = sampleReport();
  base.findings[0]!.severity = 'high';
  base.findings[0]!.confidence = 'high';
  const current = structuredClone(base);
  current.auditId = '00000000-0000-4000-8000-000000000002';
  current.createdAt = '2026-09-08T13:00:00.000Z';
  const comparison = compareReports(base, current);

  const balanced = buildPolicyResult(current, 'balanced', comparison);
  assert.equal(balanced.criteria.findingScope, 'new-only');
  assert.equal(balanced.summary.gatedFindings, 0);
  assert.equal(balanced.summary.excludedLegacyFindings, 1);

  const strict = buildPolicyResult(current, 'strict', comparison);
  assert.equal(strict.criteria.findingScope, 'all-unresolved');
  assert.equal(strict.summary.gatedFindings, 1);
});

test('accepted and active suppressed findings do not gate, but expired suppression does', () => {
  const report = sampleReport();
  report.findings[0]!.severity = 'high';
  report.findings[0]!.confidence = 'high';
  report.findings[0]!.suppression = {
    reason: 'Temporary migration exception.',
    createdAt: '2026-09-01T00:00:00.000Z',
    expiresAt: '2026-09-09T00:00:00.000Z',
  };
  assert.equal(buildPolicyResult(report, 'balanced').summary.gatedFindings, 0);

  report.findings[0]!.suppression.expiresAt = '2026-09-08T00:00:00.000Z';
  assert.equal(buildPolicyResult(report, 'balanced').summary.gatedFindings, 1);

  report.findings[0]!.disposition = 'accepted_risk';
  assert.equal(buildPolicyResult(report, 'balanced').summary.gatedFindings, 0);
});
