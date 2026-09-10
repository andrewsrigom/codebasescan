import { z } from 'zod';
import type { AuditOptions, AuditReport } from './types.ts';

const boundedText = z.string().max(1_000_000);
const shortText = z.string().max(10_000);
const evidence = z.looseObject({
  id: shortText,
  kind: z.enum(['source', 'declared', 'observed', 'dependency', 'inferred', 'history']).optional(),
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
  exposure: z.enum(['potentially_public', 'authenticated', 'local', 'unknown']).optional(),
  priority: z.number().int().min(0).max(100).optional(),
  suppression: z
    .looseObject({
      reason: shortText,
      createdAt: shortText,
      expiresAt: shortText.optional(),
    })
    .optional(),
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
  source: z.enum([
    'builtin',
    'posture',
    'ast',
    'next',
    'react',
    'supply-chain',
    'http-probe',
    'osv',
    'semgrep',
    'gitleaks',
  ]),
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
  disposition: z.enum(['needs_review', 'confirmed', 'fixed', 'false_positive', 'accepted_risk']),
  confidence: z.enum(['low', 'medium', 'high']).optional(),
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
      reachability: z.enum(['referenced', 'not_found', 'unknown']).optional(),
      lockfile: shortText,
      advisoryModified: shortText.optional(),
    })
    .optional(),
  secret: z
    .looseObject({
      classification: z.enum(['probable', 'fixture_candidate', 'historical']),
      commit: shortText.optional(),
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
        .array(z.enum(['source', 'declared', 'observed', 'dependency', 'inferred', 'history']))
        .max(100),
    })
    .optional(),
  review: z
    .looseObject({
      decision: z.enum(['needs_review', 'confirmed', 'fixed', 'false_positive', 'accepted_risk']),
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
  parentChains: z.array(z.array(shortText).min(2).max(14)).max(3).optional(),
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
    lockfileBytes: z.number().int().positive().optional(),
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
        id: z.enum([
          'nextjs-app-router',
          'nextjs-pages-router',
          'express',
          'prisma',
          'drizzle',
          'supabase',
          'authjs',
          'trpc',
          'graphql',
          'zod',
          'joi',
          'valibot',
        ]),
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

const mechanicalAnalysis = z.looseObject({
  schemaVersion: z.literal(1),
  architecture: z
    .looseObject({
      schemaVersion: z.literal(1),
      modules: z.number().int().nonnegative(),
      localDependencies: z.number().int().nonnegative(),
      cycleCount: z.number().int().nonnegative().optional(),
      cycles: z
        .array(
          z.looseObject({
            id: shortText,
            files: z.array(shortText).min(2).max(100),
          }),
        )
        .max(100),
      orphanCount: z.number().int().nonnegative().optional(),
      orphanCandidates: z.array(shortText).max(200),
      hotspotCount: z.number().int().nonnegative().optional(),
      hotspots: z
        .array(
          z.looseObject({
            file: shortText,
            incoming: z.number().int().nonnegative(),
            outgoing: z.number().int().nonnegative(),
            instability: z.number().min(0).max(1),
          }),
        )
        .max(100),
      truncated: z.boolean(),
    })
    .optional(),
  duplication: z
    .looseObject({
      schemaVersion: z.literal(1),
      files: z.number().int().nonnegative(),
      lines: z.number().int().nonnegative(),
      tokens: z.number().int().nonnegative(),
      clones: z.number().int().nonnegative(),
      duplicatedLines: z.number().int().nonnegative(),
      percentage: z.number().min(0).max(100),
      blocks: z
        .array(
          z.looseObject({
            id: shortText,
            kind: z.enum(['exact', 'similar']),
            format: shortText,
            lines: z.number().int().positive(),
            tokens: z.number().int().positive(),
            first: z.looseObject({
              file: shortText,
              startLine: z.number().int().positive(),
              endLine: z.number().int().positive(),
            }),
            second: z.looseObject({
              file: shortText,
              startLine: z.number().int().positive(),
              endLine: z.number().int().positive(),
            }),
          }),
        )
        .max(100),
      truncated: z.boolean(),
    })
    .optional(),
});

const supplyChainAnalysis = z.looseObject({
  schemaVersion: z.literal(1),
  manifests: z.number().int().nonnegative(),
  lockfiles: z.number().int().nonnegative(),
  lifecycleScripts: z.number().int().nonnegative(),
  dependencySpecs: z.number().int().nonnegative(),
  lockEntries: z.number().int().nonnegative(),
  issueCounts: z.looseObject({
    dangerousLifecycleScripts: z.number().int().nonnegative(),
    unsafeDependencySpecs: z.number().int().nonnegative(),
    weakLockfileIntegrity: z.number().int().nonnegative(),
    insecureLockfileUrls: z.number().int().nonnegative(),
    unexpectedLockfileHosts: z.number().int().nonnegative(),
    manifestLockMismatches: z.number().int().nonnegative(),
  }),
  truncated: z.boolean(),
});

const codeQualityAnalysis = z.looseObject({
  schemaVersion: z.literal(1),
  filesAnalyzed: z.number().int().nonnegative(),
  functionsAnalyzed: z.number().int().nonnegative(),
  hotspotCount: z.number().int().nonnegative().optional(),
  hotspots: z
    .array(
      z.looseObject({
        file: shortText,
        line: z.number().int().positive(),
        name: shortText,
        lines: z.number().int().positive(),
        parameters: z.number().int().nonnegative(),
        complexity: z.number().int().positive(),
      }),
    )
    .max(200),
  deadCode: z
    .looseObject({
      schemaVersion: z.literal(1),
      unusedFileCount: z.number().int().nonnegative().optional(),
      unusedFiles: z.array(shortText).max(300),
      unusedDependencyCount: z.number().int().nonnegative().optional(),
      unusedDependencies: z.array(shortText).max(300),
      unlistedDependencyCount: z.number().int().nonnegative().optional(),
      unlistedDependencies: z
        .array(
          z.looseObject({ file: shortText, line: z.number().int().positive(), name: shortText }),
        )
        .max(300),
      unusedExportCount: z.number().int().nonnegative().optional(),
      unusedExports: z
        .array(
          z.looseObject({ file: shortText, line: z.number().int().positive(), name: shortText }),
        )
        .max(300),
      unusedTypeCount: z.number().int().nonnegative().optional(),
      unusedTypes: z
        .array(
          z.looseObject({ file: shortText, line: z.number().int().positive(), name: shortText }),
        )
        .max(300),
      truncated: z.boolean(),
    })
    .optional(),
  coverageArtifacts: z
    .array(
      z.looseObject({
        file: shortText,
        lines: z.number().min(0).max(100).optional(),
        statements: z.number().min(0).max(100).optional(),
        functions: z.number().min(0).max(100).optional(),
        branches: z.number().min(0).max(100).optional(),
      }),
    )
    .max(10),
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
        review: z
          .object({
            decision: z.enum([
              'verified_external',
              'accepted_gap',
              'not_applicable',
              'needs_follow_up',
            ]),
            note: shortText,
            at: shortText,
          })
          .optional(),
      }),
    )
    .max(1_000),
  summary: z.record(controlStatus, z.number().int().nonnegative()),
});

export const auditReportSchema = z.looseObject({
  schemaVersion: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4), z.literal(5)]),
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
  mechanicalAnalysis: mechanicalAnalysis.optional(),
  supplyChainAnalysis: supplyChainAnalysis.optional(),
  codeQualityAnalysis: codeQualityAnalysis.optional(),
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
  gitHistorySecrets: z.boolean().optional(),
  scopePreflight: scopePreflight.optional(),
});

export function parseAuditReport(value: unknown): AuditReport {
  return auditReportSchema.parse(value) as AuditReport;
}

export function parseStoredAuditOptions(value: unknown): AuditOptions {
  return storedOptionsSchema.parse(value) as AuditOptions;
}
