import { z } from 'zod';
import type { SuppressionLedger } from './suppression-ledger.ts';

const shortText = z.string().min(1).max(10_000);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const relativePath = z
  .string()
  .min(1)
  .max(1_000)
  .regex(/^(?!.*(?:^|\/)\.\.?($|\/))(?!\/)(?![A-Za-z]:)[^\\\0]+$/);
const entry = z.object({
  fingerprint: digest,
  ruleId: shortText,
  paths: z.array(relativePath).min(1).max(1_000),
  evidenceFileDigests: z.array(digest).min(1).max(1_000),
  sourceAuditId: shortText,
  sourceSnapshotDigest: digest,
  owner: z.string().min(2).max(1_000),
  justification: z.string().min(12).max(10_000),
  evidence: z.string().min(12).max(10_000),
  createdAt: z.iso.datetime(),
  expiresAt: z.iso.datetime().optional(),
});
const schema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal('codebasescan-suppression-ledger'),
  projectName: shortText,
  updatedAt: z.iso.datetime(),
  entries: z.array(entry).max(100_000),
});

export function parseSuppressionLedger(value: unknown): SuppressionLedger {
  return schema.parse(value) as SuppressionLedger;
}

export function suppressionLedgerJsonSchema(): unknown {
  return z.toJSONSchema(schema, { target: 'draft-07', unrepresentable: 'throw' });
}
