import { z } from 'zod';
import type { PolicyResult } from './policy.ts';
import { policyProfiles } from './policy.ts';
import { severities } from './types.ts';

const shortText = z.string().min(1).max(10_000);
const nonnegative = z.number().int().nonnegative();
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const coverageStatus = z.enum([
  'COMPLETE',
  'PARTIAL',
  'FAILED',
  'NOT RUN',
  'DISABLED',
  'NOT SUPPORTED',
  'NOT PERFORMED',
]);

const schema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal('traceward-policy-result'),
  generatedAt: z.iso.datetime(),
  auditId: shortText,
  snapshotDigest: digest,
  profile: z.enum(policyProfiles),
  decision: z.enum(['advisory', 'pass', 'fail']),
  exitCode: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  baselineAuditId: shortText.optional(),
  criteria: z.object({
    minimumSeverity: z.enum(severities).nullable(),
    minimumConfidence: z.literal('medium').nullable(),
    findingScope: z.enum(['all-unresolved', 'new-only']),
    coverageGate: z.enum(['none', 'failed-or-truncated', 'partial-failed-or-truncated']),
  }),
  summary: z.object({
    reportFindings: nonnegative,
    consideredFindings: nonnegative,
    excludedLegacyFindings: nonnegative,
    excludedByDisposition: nonnegative,
    excludedByActiveSuppression: nonnegative,
    matchedFindings: nonnegative,
    gatedFindings: nonnegative,
    coverageIssues: nonnegative,
    blockingCoverageIssues: nonnegative,
  }),
  matchedFindingIds: z.array(shortText).max(100_000),
  gatedFindingIds: z.array(shortText).max(100_000),
  coverageIssues: z
    .array(
      z.object({
        id: shortText,
        status: coverageStatus,
        blocking: z.boolean(),
        detail: shortText,
      }),
    )
    .max(1_000),
  limitations: z.array(shortText).max(100),
});

export function parsePolicyResult(value: unknown): PolicyResult {
  return schema.parse(value) as PolicyResult;
}

export function policyResultJsonSchema(): unknown {
  return z.toJSONSchema(schema, { target: 'draft-07', unrepresentable: 'throw' });
}
