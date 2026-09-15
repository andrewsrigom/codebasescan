import { z } from 'zod';
import type { TriageLedger } from './triage-ledger.ts';

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const entry = z.strictObject({
  fingerprint: digest,
  ruleId: z.string().min(1).max(10_000),
  evidenceFileDigests: z.array(digest).min(1).max(100),
  evidenceIds: z.array(z.string().min(1).max(10_000)).min(1).max(16),
  sourceAuditId: z.string().min(1).max(10_000),
  sourceSnapshotDigest: digest,
  assessment: z.enum(['likely_valid', 'likely_false_positive', 'inconclusive']),
  note: z.string().min(12).max(10_000),
  assessedAt: z.iso.datetime(),
  origin: z.literal('external-agent'),
});
const schema = z.strictObject({
  schemaVersion: z.literal(1),
  kind: z.literal('codebasescan-triage-ledger'),
  projectName: z.string().min(1).max(10_000),
  updatedAt: z.iso.datetime(),
  entries: z.array(entry).max(10_000),
});

export function parseTriageLedger(value: unknown): TriageLedger {
  return schema.parse(value) as TriageLedger;
}

export function triageLedgerJsonSchema(): unknown {
  return z.toJSONSchema(schema, { target: 'draft-07', unrepresentable: 'throw' });
}
