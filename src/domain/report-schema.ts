import { z } from 'zod';
import type { AuditOptions, AuditReport } from './types.ts';

const boundedText = z.string().max(1_000_000);
const shortText = z.string().max(10_000);
const evidence = z.looseObject({
  id: shortText,
  kind: z.enum(['source', 'declared', 'observed', 'dependency', 'inferred']).optional(),
  scope: z.enum(['runtime', 'test', 'example']).optional(),
  file: shortText,
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  excerpt: boundedText,
  fileDigest: shortText,
  observation: shortText,
  url: shortText.optional(),
  observedAt: shortText.optional(),
});

const analysis = z.looseObject({
  kind: z.enum(['deterministic', 'ollama', 'openai']),
  assessment: z.enum(['needs_review', 'likely_issue', 'likely_false_positive', 'inconclusive']),
  explanation: shortText,
  evidenceIds: z.array(shortText).max(100),
  limitations: z.array(shortText).max(100),
  controlsFound: z.array(shortText).max(100).optional(),
  missingEvidence: z.array(shortText).max(100).optional(),
  impact: shortText.optional(),
  preconditions: z.array(shortText).max(100).optional(),
  remediationOptions: z.array(shortText).max(100).optional(),
  verificationPlan: z.array(shortText).max(100).optional(),
  inspectedFiles: z.array(shortText).max(1_000),
  rounds: z.number().int().nonnegative().max(10),
  confidence: z.enum(['low', 'medium', 'high']).optional(),
  provider: z.enum(['ollama', 'openai']).optional(),
  model: shortText.optional(),
  promptVersion: shortText.optional(),
  contextFilesSent: z.array(shortText).max(1_000).optional(),
  contextIdsSent: z.array(shortText).max(1_000).optional(),
  contextCharactersSent: z.number().int().nonnegative().optional(),
  contextTruncated: z.boolean().optional(),
  redactionApplied: z.boolean().optional(),
  cached: z.boolean().optional(),
  tokenUsage: z
    .looseObject({
      inputTokens: z.number().int().nonnegative(),
      outputTokens: z.number().int().nonnegative(),
      cachedInputTokens: z.number().int().nonnegative().optional(),
    })
    .optional(),
  approximateCostUsd: z.number().nonnegative().optional(),
});

const finding = z.looseObject({
  id: shortText,
  fingerprint: shortText,
  ruleId: shortText,
  source: z.enum(['builtin', 'posture', 'ast', 'http-probe', 'osv', 'semgrep', 'gitleaks']),
  title: shortText,
  category: z.enum([
    'authentication',
    'authorization',
    'injection',
    'secrets',
    'configuration',
    'ai-security',
    'dependencies',
    'code',
  ]),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  sourceSeverity: shortText,
  description: shortText,
  remediation: shortText,
  cwe: z.array(shortText).max(100),
  evidence: z.array(evidence).min(1).max(1_000),
  disposition: z.enum(['needs_review', 'confirmed', 'false_positive', 'accepted_risk']),
  analysis: analysis.optional(),
  runtimeVerification: z
    .looseObject({
      status: z.enum(['corroborated', 'observed_safe', 'different']),
      observation: shortText,
      url: shortText,
      observedAt: shortText,
    })
    .optional(),
  vulnerability: z
    .looseObject({
      id: shortText,
      aliases: z.array(shortText).max(1_000),
      package: shortText,
      version: shortText,
      fixedVersions: z.array(shortText).max(1_000),
      severity: z.array(z.looseObject({ type: shortText, score: shortText })).max(1_000),
      relationship: z.enum(['direct', 'transitive', 'unknown']),
      lockfile: shortText,
      advisoryModified: shortText.optional(),
    })
    .optional(),
  provenance: z
    .looseObject({
      detector: z.enum([
        'traceward-heuristic',
        'traceward-ast',
        'scanner',
        'runtime-probe',
        'advisory-database',
      ]),
      scanner: shortText,
      ruleId: shortText,
      scannerVersion: shortText.optional(),
      originalSeverity: shortText,
      detectedAt: shortText,
      evidenceKinds: z
        .array(z.enum(['source', 'declared', 'observed', 'dependency', 'inferred']))
        .max(100),
    })
    .optional(),
  review: z
    .looseObject({
      decision: z.enum(['needs_review', 'confirmed', 'false_positive', 'accepted_risk']),
      note: shortText,
      at: shortText,
    })
    .optional(),
});

const scanner = z.looseObject({
  id: shortText,
  name: shortText,
  status: z.enum(['completed', 'partial', 'skipped', 'failed']),
  durationMs: z.number().nonnegative(),
  findings: z.number().int().nonnegative(),
  detail: shortText,
  version: shortText.optional(),
});

const dependency = z.looseObject({
  name: shortText,
  requestedVersion: shortText,
  resolvedVersion: shortText.optional(),
  manifest: shortText,
  scope: z.enum(['runtime', 'development']),
  relationship: z.enum(['direct', 'transitive', 'unknown']).optional(),
  lockfile: shortText.optional(),
  lockfileLine: z.number().int().positive().optional(),
});

const scopePreflight = z.looseObject({
  schemaVersion: z.literal(1),
  estimatedAt: shortText,
  supportedFiles: z.number().int().nonnegative(),
  supportedBytes: z.number().int().nonnegative(),
  scopeFiles: z
    .object({
      runtime: z.number().int().nonnegative(),
      test: z.number().int().nonnegative(),
      example: z.number().int().nonnegative(),
    })
    .optional(),
  oversizedFiles: z.number().int().nonnegative(),
  visitedEntries: z.number().int().nonnegative(),
  predictedTruncated: z.boolean(),
  reasons: z.array(shortText).max(100),
  limits: z.looseObject({
    files: z.number().int().positive(),
    bytesPerFile: z.number().int().positive(),
    totalBytes: z.number().int().positive(),
  }),
  truncationApproved: z.boolean(),
});

const projectProfile = z.looseObject({
  schemaVersion: z.literal(1),
  status: z.enum(['complete', 'partial', 'unsupported']),
  languages: z.array(z.enum(['typescript', 'javascript'])).max(10),
  frameworks: z
    .array(
      z.looseObject({
        id: z.enum(['nextjs-app-router', 'nextjs-pages-router', 'express', 'prisma', 'supabase']),
        name: shortText,
        file: shortText,
        line: z.number().int().positive(),
      }),
    )
    .max(100),
  entrypoints: z.array(z.looseObject({ id: shortText, file: shortText })).max(10_000),
  symbols: z.array(z.looseObject({ id: shortText, file: shortText })).max(20_000),
  imports: z.array(z.looseObject({ id: shortText, file: shortText })).max(20_000),
  calls: z.array(z.looseObject({ id: shortText, file: shortText })).max(50_000),
  facts: z.array(z.looseObject({ id: shortText, file: shortText })).max(50_000),
  filesAnalyzed: z.number().int().nonnegative(),
  nodesAnalyzed: z.number().int().nonnegative(),
  issues: z.array(shortText).max(10_000),
  truncated: z.boolean(),
});

const controlStatus = z.enum([
  'EVIDENCED',
  'GAP_CANDIDATE',
  'UNVERIFIED',
  'NOT_APPLICABLE',
  'PARTIAL',
  'FAILED',
]);
const checklist = z.looseObject({
  schemaVersion: z.literal(1),
  packId: z.literal('traceward-web-application'),
  packVersion: shortText,
  controls: z
    .array(
      z.looseObject({
        id: shortText,
        domain: shortText,
        title: shortText,
        status: controlStatus,
        rationale: shortText,
        applicability: shortText,
        evidence: z.array(z.looseObject({ kind: shortText, id: shortText })).max(10_000),
        verification: shortText,
        limitations: z.array(shortText).max(1_000),
      }),
    )
    .max(1_000),
  summary: z.record(controlStatus, z.number().int().nonnegative()),
});

export const auditReportSchema = z.looseObject({
  schemaVersion: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  auditId: shortText,
  projectName: shortText,
  createdAt: shortText,
  snapshotDigest: shortText,
  filesAnalyzed: z.number().int().nonnegative(),
  skipped: z.record(z.string(), z.number().int().nonnegative()),
  truncated: z.boolean(),
  aiMode: z.enum(['disabled', 'ollama', 'openai']),
  findings: z.array(finding).max(10_000),
  scanners: z.array(scanner).max(1_000),
  dependencies: z.array(dependency).max(100_000),
  scopePreflight: scopePreflight.optional(),
  projectProfile: projectProfile.optional(),
  checklist: checklist.optional(),
  httpProbe: z.looseObject({ requestedUrl: shortText, finalUrl: shortText }).optional(),
  coverage: z
    .array(z.looseObject({ id: shortText, status: shortText }))
    .max(1_000)
    .optional(),
  aiUsage: z
    .looseObject({
      provider: z.enum(['ollama', 'openai']),
      models: z.array(shortText).max(100),
      calls: z.number().int().nonnegative(),
      cacheHits: z.number().int().nonnegative(),
      inputTokens: z.number().int().nonnegative(),
      outputTokens: z.number().int().nonnegative(),
      contextFilesSent: z.array(shortText).max(10_000),
      contextIdsSent: z.array(shortText).max(10_000).optional(),
      redactionApplied: z.boolean(),
    })
    .optional(),
  limitations: z.array(shortText).max(10_000),
  publication: z.enum(['draft', 'reviewed']),
  reviewNote: shortText.optional(),
});

const storedOptionsSchema = z.looseObject({
  httpProbe: z
    .looseObject({
      url: shortText,
      allowPrivateNetwork: z.boolean(),
    })
    .optional(),
  scopePreflight: scopePreflight.optional(),
});

export function parseAuditReport(value: unknown): AuditReport {
  return auditReportSchema.parse(value) as AuditReport;
}

export function parseStoredAuditOptions(value: unknown): AuditOptions {
  return storedOptionsSchema.parse(value) as AuditOptions;
}
