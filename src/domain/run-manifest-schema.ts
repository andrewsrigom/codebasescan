import { z } from 'zod';
import type { RunManifest } from './run-manifest.ts';
import { auditModes } from './types.ts';

const shortText = z.string().min(1).max(10_000);
const nonnegative = z.number().int().nonnegative();
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const scannerStatus = z.enum(['completed', 'partial', 'skipped', 'failed']);
const coverageStatus = z.enum([
  'COMPLETE',
  'PARTIAL',
  'FAILED',
  'NOT RUN',
  'DISABLED',
  'NOT SUPPORTED',
  'NOT PERFORMED',
]);

const scopePreflight = z.object({
  schemaVersion: z.literal(1),
  estimatedAt: z.iso.datetime(),
  supportedFiles: nonnegative,
  supportedBytes: nonnegative,
  scopeFiles: z
    .object({ runtime: nonnegative, test: nonnegative, example: nonnegative })
    .optional(),
  oversizedFiles: nonnegative,
  visitedEntries: nonnegative,
  predictedTruncated: z.boolean(),
  reasons: z.array(shortText).max(100),
  limits: z.object({
    files: nonnegative,
    bytesPerFile: nonnegative,
    lockfileBytes: nonnegative.optional(),
    totalBytes: nonnegative,
  }),
  truncationApproved: z.boolean(),
});

const schema = z.object({
  schemaVersion: z.literal(2),
  kind: z.literal('codebasescan-audit-run'),
  codebasescanVersion: shortText,
  workflowVersion: shortText,
  packVersion: shortText,
  audit: z.object({
    id: shortText,
    projectName: shortText,
    createdAt: z.iso.datetime(),
    snapshotDigest: digest,
    reportSchemaVersion: z.number().int().min(1).max(14),
    aiMode: z.enum(['disabled', 'ollama', 'openai']),
    publication: z.enum(['draft', 'reviewed']),
  }),
  modes: z.object({
    selectionAvailable: z.boolean(),
    requested: z.array(z.enum(auditModes)).max(auditModes.length),
    effective: z
      .array(z.object({ id: z.enum(auditModes), version: shortText, enabled: z.boolean() }))
      .max(auditModes.length),
  }),
  scope: z.object({
    filesAnalyzed: nonnegative,
    skipped: z.record(z.string(), nonnegative),
    truncated: z.boolean(),
    preflight: scopePreflight.nullable(),
  }),
  execution: z.object({
    scannerDurationMs: nonnegative,
    scannerStatus: z.record(scannerStatus, nonnegative),
    cache: z.object({
      eligible: nonnegative,
      hits: nonnegative,
      misses: nonnegative,
    }),
    scanners: z
      .array(
        z.object({
          id: shortText,
          name: shortText,
          status: scannerStatus,
          durationMs: nonnegative,
          findings: nonnegative,
          detail: shortText,
          version: shortText.optional(),
          cache: z
            .object({
              status: z.enum(['hit', 'miss']),
              key: digest,
              storedAt: z.iso.datetime({ offset: true }).optional(),
              sourceDurationMs: nonnegative.optional(),
            })
            .optional(),
        }),
      )
      .max(1_000),
  }),
  coverage: z.object({
    status: z.record(coverageStatus, nonnegative),
    capabilities: z
      .array(
        z.object({
          id: shortText,
          label: shortText,
          status: coverageStatus,
          detail: shortText,
          findings: nonnegative.optional(),
          version: shortText.optional(),
        }),
      )
      .max(1_000),
  }),
  limitations: z.array(shortText).max(1_000),
  outputs: z
    .array(
      z.object({
        path: z
          .string()
          .min(1)
          .max(1_000)
          .regex(/^(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9][A-Za-z0-9._/-]*$/),
        mediaType: shortText,
        bytes: nonnegative,
        sha256: digest,
      }),
    )
    .max(1_000),
});

export function parseRunManifest(value: unknown): RunManifest {
  return schema.parse(value) as RunManifest;
}

export function runManifestJsonSchema(): unknown {
  return z.toJSONSchema(schema, { target: 'draft-07', unrepresentable: 'throw' });
}
