import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applySuppressionLedger,
  upsertSuppressionLedger,
} from '../../src/domain/suppression-ledger.ts';
import { parseSuppressionLedger } from '../../src/domain/suppression-ledger-schema.ts';
import { parseAuditReport } from '../../src/domain/report-schema.ts';
import { sampleReport } from '../helpers.ts';

const input = {
  findingId: '',
  owner: 'Security team',
  justification: 'Accepted during the bounded migration window.',
  evidence: 'Change record CR-123 documents the compensating control.',
  createdAt: '2026-09-08T12:30:00.000Z',
  expiresAt: '2026-10-08T12:30:00.000Z',
};

test('portable suppression requires and matches an exact source target', () => {
  const report = sampleReport();
  const ledger = parseSuppressionLedger(
    upsertSuppressionLedger(undefined, report, {
      ...input,
      findingId: report.findings[0]!.id,
    }),
  );
  const applied = parseAuditReport(
    applySuppressionLedger(report, ledger, '2026-09-08T13:00:00.000Z'),
  );
  assert.equal(applied.schemaVersion, 17);
  assert.equal(applied.suppressionImport?.applied, 1);
  assert.equal(applied.findings[0]?.suppression?.owner, 'Security team');
  assert.equal(applied.findings[0]?.suppression?.target?.ruleId, report.findings[0]?.ruleId);
});

test('stale, expired, and unmatched entries remain counted without suppressing evidence', () => {
  const report = sampleReport();
  const ledger = upsertSuppressionLedger(undefined, report, {
    ...input,
    findingId: report.findings[0]!.id,
  });
  const stale = structuredClone(ledger);
  stale.entries[0]!.ruleId = 'changed-rule';
  let applied = applySuppressionLedger(report, stale);
  assert.equal(applied.suppressionImport?.stale, 1);
  assert.equal(applied.findings[0]?.suppression, undefined);

  const expired = structuredClone(ledger);
  expired.entries[0]!.expiresAt = '2026-09-08T11:00:00.000Z';
  applied = applySuppressionLedger(report, expired);
  assert.equal(applied.suppressionImport?.expired, 1);

  const unmatched = structuredClone(ledger);
  unmatched.entries[0]!.fingerprint = 'b'.repeat(64);
  applied = applySuppressionLedger(report, unmatched);
  assert.equal(applied.suppressionImport?.unmatched, 1);
});

test('suppression ledger rejects unsafe paths and weak rationale', () => {
  const report = sampleReport();
  assert.throws(() =>
    upsertSuppressionLedger(undefined, report, {
      ...input,
      findingId: report.findings[0]!.id,
      justification: 'too short',
    }),
  );
  const ledger = upsertSuppressionLedger(undefined, report, {
    ...input,
    findingId: report.findings[0]!.id,
  });
  ledger.entries[0]!.paths = ['../secret'];
  assert.throws(() => parseSuppressionLedger(ledger));
});
