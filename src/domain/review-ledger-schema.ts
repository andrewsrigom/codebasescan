import { z } from 'zod';
import type { ReviewLedger } from './review-ledger.ts';

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const shortText = z.string().min(1).max(10_000);
const entry = z.object({
  fingerprint: digest,
  evidenceFileDigests: z.array(digest).min(1).max(100),
  sourceAuditId: shortText,
  sourceSnapshotDigest: digest,
  decision: z.enum(['confirmed', 'false_positive', 'accepted_risk']),
  note: z.string().min(12).max(10_000),
  reviewedAt: z.iso.datetime(),
});
const schema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal('codebasescan-review-ledger'),
  projectName: shortText,
  updatedAt: z.iso.datetime(),
  entries: z.array(entry).max(10_000),
});

export function parseReviewLedger(value: unknown): ReviewLedger {
  return schema.parse(value) as ReviewLedger;
}

export function reviewLedgerJsonSchema(): unknown {
  return z.toJSONSchema(schema, { target: 'draft-07', unrepresentable: 'throw' });
}
