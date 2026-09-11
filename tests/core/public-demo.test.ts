import test from 'node:test';
import assert from 'node:assert/strict';
import { upsertCalibrationEntry } from '../../src/domain/calibration.ts';
import { buildPublicDemo } from '../../src/reporting/public-demo.ts';
import { sampleReport } from '../helpers.ts';

test('public demo keeps retained candidates and removes private identifiers', () => {
  const report = sampleReport();
  report.projectName = 'private-saas';
  report.findings[0]!.evidence[0]!.file = 'packages/private-saas/src/server.ts';
  const dismissed = structuredClone(report.findings[0]!);
  dismissed.id = 'dismissed-finding';
  dismissed.fingerprint = 'b'.repeat(64);
  dismissed.title = 'Dismissed private-saas candidate';
  report.findings.push(dismissed);

  let ledger = upsertCalibrationEntry(undefined, report, {
    findingId: report.findings[0]!.id,
    outcome: 'true_positive',
    evidenceAccuracy: 'correct',
    locationAccuracy: 'correct',
    explanationQuality: 'clear',
    note: 'Retained after reviewing the complete source context.',
    reviewer: 'model-assisted-test-review',
    reviewedAt: '2026-09-11T12:00:00.000Z',
  });
  ledger = upsertCalibrationEntry(ledger, report, {
    findingId: dismissed.id,
    outcome: 'false_positive',
    evidenceAccuracy: 'incorrect',
    locationAccuracy: 'correct',
    explanationQuality: 'clear',
    note: 'Dismissed after reviewing the complete source context.',
    reviewer: 'model-assisted-test-review',
    reviewedAt: '2026-09-11T12:00:00.000Z',
  });

  const demo = buildPublicDemo(report, ledger, {
    projectName: 'Example SaaS Application',
    replacements: [{ from: 'private', to: 'example' }],
  });

  assert.equal(demo.retainedFindings, 1);
  assert.equal(demo.report.findings.length, 1);
  assert.equal(demo.report.projectName, 'Example SaaS Application');
  assert.ok(demo.html.includes('Anonymized public example'));
  assert.ok(demo.html.includes('Public example report'));
  assert.ok(!demo.html.toLowerCase().includes('private-saas'));
  assert.ok(!demo.html.includes('Dismissed private-saas candidate'));
  assert.ok(!demo.html.includes('agent-plan.json'));
});
