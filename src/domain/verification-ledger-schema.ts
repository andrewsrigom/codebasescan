import { z } from 'zod';
import type { VerificationLedger } from './verification-ledger.ts';

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const shortText = z.string().min(1).max(10_000);
const argument = z
  .string()
  .min(1)
  .max(1_000)
  .refine((value) => !value.includes('\0'));
const auditReference = z.object({ auditId: shortText, snapshotDigest: digest }).strict();
const execution = z
  .object({
    id: z.string().regex(/^execution-[a-f0-9]{16}$/),
    kind: z.enum(['project_test', 'project_build']),
    argv: z.array(argument).min(1).max(32),
    workingDirectory: z.literal('project_root'),
    startedAt: z.iso.datetime(),
    durationMs: z.number().int().nonnegative().max(86_400_000),
    exitCode: z.number().int().min(0).max(255),
    outputSha256: digest,
    outputBytes: z.number().int().nonnegative().max(1_000_000_000),
    outputTruncated: z.boolean(),
    executor: z.string().min(1).max(200),
    network: z.enum(['denied', 'used', 'unknown']),
  })
  .strict();
const schema = z
  .object({
    schemaVersion: z.literal(1),
    kind: z.literal('traceward-verification-ledger'),
    createdAt: z.iso.datetime(),
    project: z
      .object({
        name: shortText,
        before: auditReference,
        after: auditReference,
      })
      .strict(),
    planDigest: digest,
    executions: z.array(execution).max(100),
  })
  .strict();

export function parseVerificationLedger(value: unknown): VerificationLedger {
  const ledger = schema.parse(value) as VerificationLedger;
  const ids = new Set<string>();
  const commands = new Set<string>();
  for (const item of ledger.executions) {
    if (ids.has(item.id)) throw new Error(`Duplicate verification execution ID: ${item.id}`);
    ids.add(item.id);
    const command = JSON.stringify([item.kind, item.workingDirectory, item.argv]);
    if (commands.has(command))
      throw new Error('Verification ledger contains duplicate command evidence.');
    commands.add(command);
  }
  return ledger;
}

export function verificationLedgerJsonSchema(): unknown {
  return z.toJSONSchema(schema, { target: 'draft-07', unrepresentable: 'throw' });
}
