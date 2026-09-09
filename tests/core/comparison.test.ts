import test from 'node:test';
import assert from 'node:assert/strict';
import { compareReports } from '../../src/domain/comparison.ts';
import { sampleReport } from '../helpers.ts';
import { baselineCiGate, ciGate } from '../../src/domain/ci.ts';

test('report comparison separates new, resolved, unchanged, and severity changes', () => {
  const base = sampleReport();
  base.auditId = '00000000-0000-4000-8000-000000000001';
  const unchanged = { ...base.findings[0]!, severity: 'critical' as const };
  const added = {
    ...base.findings[0]!,
    id: 'new-id',
    fingerprint: 'new-fingerprint',
    ruleId: 'TW-NEW',
  };
  const current = sampleReport();
  current.auditId = '00000000-0000-4000-8000-000000000002';
  current.findings = [unchanged, added];
  const comparison = compareReports(base, current);
  assert.equal(comparison.newFindings.length, 1);
  assert.equal(comparison.resolvedFindings.length, 0);
  assert.equal(comparison.unchangedFindings.length, 1);
  assert.deepEqual(comparison.severityChanges[0], {
    finding: {
      id: unchanged.id,
      fingerprint: unchanged.fingerprint,
      ruleId: unchanged.ruleId,
      title: unchanged.title,
      severity: 'critical',
    },
    before: 'high',
    after: 'critical',
  });

  current.findings = [added];
  assert.equal(compareReports(base, current).resolvedFindings.length, 1);
});

test('CI severity gates use meaningful exit codes', () => {
  const report = sampleReport();
  assert.deepEqual(ciGate(report, 'critical'), { exitCode: 0, gatedFindings: 0 });
  assert.deepEqual(ciGate(report, 'high'), { exitCode: 1, gatedFindings: 1 });
  report.findings[0]!.disposition = 'accepted_risk';
  assert.deepEqual(ciGate(report, 'high'), { exitCode: 0, gatedFindings: 0 });
  report.findings[0]!.disposition = 'fixed';
  assert.deepEqual(ciGate(report, 'high'), { exitCode: 0, gatedFindings: 0 });
  report.findings[0]!.disposition = 'needs_review';
  report.findings[0]!.suppression = {
    reason: 'Project exception with reviewed rationale.',
    createdAt: '2026-09-09T00:00:00.000Z',
  };
  assert.deepEqual(ciGate(report, 'high'), { exitCode: 0, gatedFindings: 0 });
});

test('baseline CI gate counts only new findings at the selected severity', () => {
  const base = sampleReport();
  const current = sampleReport();
  current.findings = [
    ...base.findings,
    {
      ...base.findings[0]!,
      id: 'new-medium-id',
      fingerprint: 'new-medium-fingerprint',
      severity: 'medium',
    },
  ];
  const comparison = compareReports(base, current);
  assert.deepEqual(baselineCiGate(comparison, 'high'), { exitCode: 0, gatedFindings: 0 });
  assert.deepEqual(baselineCiGate(comparison, 'medium'), { exitCode: 1, gatedFindings: 1 });
  current.findings.at(-1)!.suppression = {
    reason: 'Project exception with reviewed rationale.',
    createdAt: '2026-09-09T00:00:00.000Z',
  };
  assert.deepEqual(baselineCiGate(compareReports(base, current), 'medium'), {
    exitCode: 0,
    gatedFindings: 0,
  });
});
