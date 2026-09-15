import test from 'node:test';
import assert from 'node:assert/strict';
import { matchTriageLedger, upsertTriageLedger } from '../../src/domain/triage-ledger.ts';
import {
  parseTriageLedger,
  triageLedgerJsonSchema,
} from '../../src/domain/triage-ledger-schema.ts';
import { sampleReport } from '../helpers.ts';

test('agent triage stays separate from scanner and human review state', () => {
  const report = sampleReport();
  const finding = report.findings[0]!;
  const ledger = parseTriageLedger(
    upsertTriageLedger(undefined, report, {
      findingId: finding.id,
      assessment: 'likely_false_positive',
      evidenceIds: [finding.evidence[0]!.id],
      note: 'The apparent input is an inert regression fixture.',
      assessedAt: '2026-09-10T12:00:00.000Z',
    }),
  );
  assert.equal(matchTriageLedger(report, ledger)[0]?.status, 'current');
  assert.equal(report.findings[0]?.disposition, 'needs_review');

  const changed = structuredClone(report);
  changed.findings[0]!.evidence[0]!.fileDigest = 'b'.repeat(64);
  assert.equal(matchTriageLedger(changed, ledger)[0]?.status, 'stale');
  changed.findings = [];
  assert.equal(matchTriageLedger(changed, ledger)[0]?.status, 'unmatched');
});

test('agent triage requires exact cited evidence and a meaningful note', () => {
  const report = sampleReport();
  const finding = report.findings[0]!;
  assert.throws(
    () =>
      upsertTriageLedger(undefined, report, {
        findingId: finding.id,
        assessment: 'likely_valid',
        evidenceIds: ['not-in-finding'],
        note: 'This assessment cites unavailable evidence.',
      }),
    /Cite 1 to 16 evidence IDs/,
  );
  const ledger = upsertTriageLedger(undefined, report, {
    findingId: finding.id,
    assessment: 'likely_valid',
    evidenceIds: [finding.evidence[0]!.id],
    note: 'The source evidence shows an unsafe call.',
  });
  const otherProject = structuredClone(report);
  otherProject.projectName = 'unrelated';
  assert.throws(() => matchTriageLedger(otherProject, ledger), /different project/);
  assert.throws(() => parseTriageLedger({ ...ledger, extra: 'not allowed' }));
});

test('agent triage JSON Schema is versioned', () => {
  const schema = triageLedgerJsonSchema() as {
    properties?: { schemaVersion?: { const?: number } };
  };
  assert.equal(schema.properties?.schemaVersion?.const, 1);
});
