import test from 'node:test';
import assert from 'node:assert/strict';
import { applyReviewLedger, upsertReviewLedger } from '../../src/domain/review-ledger.ts';
import {
  parseReviewLedger,
  reviewLedgerJsonSchema,
} from '../../src/domain/review-ledger-schema.ts';
import { sampleReport } from '../helpers.ts';

test('portable review applies only to the same finding and source-file digest', () => {
  const source = sampleReport();
  const finding = source.findings[0]!;
  const ledger = parseReviewLedger(
    upsertReviewLedger(undefined, source, {
      findingId: finding.id,
      decision: 'false_positive',
      note: 'Confirmed inert fixture in a dedicated encryption test.',
      reviewedAt: '2026-09-10T12:00:00.000Z',
    }),
  );
  const reviewed = applyReviewLedger(structuredClone(source), ledger, '2026-09-10T13:00:00.000Z');
  assert.equal(reviewed.schemaVersion, 12);
  assert.equal(reviewed.findings[0]?.disposition, 'false_positive');
  assert.equal(reviewed.reviewImport?.applied, 1);
  assert.equal(reviewed.reviewImport?.stale, 0);

  const changed = structuredClone(source);
  changed.findings[0]!.evidence[0]!.fileDigest = 'b'.repeat(64);
  const stale = applyReviewLedger(changed, ledger, '2026-09-10T13:00:00.000Z');
  assert.equal(stale.findings[0]?.disposition, 'needs_review');
  assert.equal(stale.reviewImport?.applied, 0);
  assert.equal(stale.reviewImport?.stale, 1);
});

test('portable review rejects another project and weak rationale', () => {
  const report = sampleReport();
  assert.throws(
    () =>
      upsertReviewLedger(undefined, report, {
        findingId: report.findings[0]!.id,
        decision: 'confirmed',
        note: 'too short',
      }),
    /at least 12 characters/,
  );
  const ledger = upsertReviewLedger(undefined, report, {
    findingId: report.findings[0]!.id,
    decision: 'confirmed',
    note: 'Source evidence was independently reviewed.',
    reviewedAt: '2026-09-10T12:00:00.000Z',
  });
  const anotherProject = structuredClone(report);
  anotherProject.projectName = 'another-project';
  assert.throws(() => applyReviewLedger(anotherProject, ledger), /different project/);
});

test('portable review JSON Schema is versioned', () => {
  const schema = reviewLedgerJsonSchema() as {
    properties?: { schemaVersion?: { const?: number } };
  };
  assert.equal(schema.properties?.schemaVersion?.const, 1);
});
