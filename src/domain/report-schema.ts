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
  focusLine: z.number().int().positive().optional(),
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
    'saas',
    'next',
    'react',
    'accessibility',
    'privacy',
    'reliability',
    'environment',
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
    'accessibility',
    'privacy',
    'reliability',
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

const projectFeature = z.enum([
  'authentication',
  'tenancy',
  'billing',
  'webhooks',
  'administration',
  'uploads',
]);
const projectDataClass = z.enum([
  'credentials',
  'personal',
  'financial',
  'health',
  'location',
  'communications',
  'files',
  'analytics',
]);
const projectDataOperation = z.enum([
  'sensitive-read',
  'persistent-storage',
  'browser-storage',
  'cookie',
  'response',
  'log',
  'url-or-redirect',
  'outbound-transfer',
  'financial-operation',
]);
const projectContext = z.object({
  features: z.array(projectFeature).max(50),
  roles: z.array(shortText).max(50),
  sensitiveData: z.array(projectDataClass).max(50),
  storageBoundaries: z.array(shortText).max(50),
  externalServices: z.array(shortText).max(50),
  priorityPaths: z.array(shortText).max(50),
  outOfScopePaths: z.array(shortText).max(50),
});
const projectVerification = z.object({
  packageManager: z.enum(['npm', 'pnpm', 'yarn']),
  testScripts: z.array(shortText).max(50),
  buildScripts: z.array(shortText).max(50),
});
const projectDataMap = z.object({
  schemaVersion: z.literal(1),
  entries: z
    .array(
      z.object({
        id: shortText,
        operation: projectDataOperation,
        file: shortText,
        line: z.number().int().positive(),
        signal: shortText,
        sourceFactId: shortText,
        provenance: z.literal('observed'),
        dataClasses: z.array(z.union([projectDataClass, z.literal('unknown')])).max(20),
      }),
    )
    .max(2_000),
  summary: z.partialRecord(projectDataOperation, z.number().int().nonnegative()),
  declaredData: z.array(projectDataClass).max(50),
  declaredBoundaries: z.object({
    storage: z.array(shortText).max(50),
    externalServices: z.array(shortText).max(50),
  }),
  truncated: z.boolean(),
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
          'react',
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
        versionCoverage: z
          .object({
            requested: shortText.optional(),
            detectedMajor: z.number().int().nonnegative().optional(),
            status: z.enum(['supported', 'partial', 'unverified']),
            supportedMajors: z.array(z.number().int().nonnegative()).max(20).optional(),
            detail: shortText,
          })
          .optional(),
      }),
    )
    .max(100),
  components: z
    .array(
      z.looseObject({
        id: shortText,
        name: shortText,
        root: shortText,
        manifest: shortText,
        kind: z.enum(['root', 'package']),
        private: z.boolean().optional(),
        sourceFiles: z.number().int().nonnegative(),
      }),
    )
    .max(200)
    .optional(),
  componentEdges: z
    .array(
      z.looseObject({
        id: shortText,
        fromComponentId: shortText,
        toComponentId: shortText,
        imports: z.number().int().positive(),
        importIds: z.array(shortText).max(20),
        truncated: z.boolean(),
      }),
    )
    .max(1_000)
    .optional(),
  entrypoints: z.array(z.looseObject({ id: shortText, file: shortText })).max(10_000),
  symbols: z.array(z.looseObject({ id: shortText, file: shortText })).max(20_000),
  imports: z.array(z.looseObject({ id: shortText, file: shortText })).max(20_000),
  calls: z.array(z.looseObject({ id: shortText, file: shortText })).max(50_000),
  facts: z.array(z.looseObject({ id: shortText, file: shortText })).max(50_000),
  saasSemantics: z
    .looseObject({
      schemaVersion: z.literal(1),
      sources: z.array(shortText).max(10),
      vocabulary: z.record(shortText, z.array(shortText).max(100)),
      helpers: z.record(shortText, z.array(shortText).max(100)),
      expectedUnauthenticatedRoutes: z.array(shortText).max(100),
      context: projectContext.optional(),
      verification: projectVerification.optional(),
    })
    .optional(),
  dataMap: projectDataMap.optional(),
  filesAnalyzed: z.number().int().nonnegative(),
  nodesAnalyzed: z.number().int().nonnegative(),
  issues: z.array(shortText).max(10_000),
  truncated: z.boolean(),
});

const riskCorrelation = z.object({
  schemaVersion: z.literal(1),
  version: shortText,
  status: z.enum(['complete', 'partial', 'unsupported']),
  paths: z
    .array(
      z.object({
        id: shortText,
        entrypointId: shortText,
        route: shortText.optional(),
        methods: z.array(shortText).max(20),
        factId: shortText,
        factKind: z.enum([
          'authentication',
          'authorization',
          'validation',
          'database',
          'billing',
          'raw-sql',
          'outbound-request',
          'command-execution',
          'file-access',
          'redirect',
          'cookie',
          'browser-storage',
          'response',
          'secret-access',
          'resource-scope',
          'logging',
          'error-handling',
          'webhook-verification',
          'rate-limit',
          'idempotency',
          'csrf',
        ]),
        findingIds: z.array(shortText).max(50),
        priority: z.number().int().min(0).max(100),
        confidence: z.literal('high'),
        steps: z
          .array(
            z.object({
              kind: z.enum(['entrypoint', 'call', 'sensitive-operation']),
              referenceId: shortText,
              file: shortText,
              line: z.number().int().positive(),
              label: shortText,
            }),
          )
          .max(10),
        truncated: z.boolean(),
      }),
    )
    .max(300),
  summary: z.object({
    paths: z.number().int().nonnegative().max(300),
    entrypoints: z.number().int().nonnegative().max(10_000),
    eligibleFindings: z.number().int().nonnegative().max(10_000),
    correlatedFindings: z.number().int().nonnegative().max(10_000),
    uncorrelatedFindings: z.number().int().nonnegative().max(10_000),
    factKinds: z.partialRecord(z.string(), z.number().int().nonnegative().max(300)),
  }),
  truncated: z.boolean(),
  limitations: z.array(shortText).max(20),
});

const environmentContract = z.object({
  schemaVersion: z.literal(1),
  version: shortText,
  status: z.enum(['complete', 'partial', 'unsupported']),
  templates: z
    .array(
      z.object({
        file: shortText,
        variables: z.number().int().nonnegative().max(5_000),
      }),
    )
    .max(1_500),
  variables: z
    .array(
      z.object({
        name: shortText,
        status: z.enum(['documented', 'undocumented', 'platform-provided', 'unverified']),
        declaredIn: z.array(shortText).max(1_500),
        locations: z
          .array(
            z.object({
              file: shortText,
              line: z.number().int().positive(),
              syntax: z.enum(['process.env', 'import.meta.env']),
              context: z.enum(['server', 'client']),
            }),
          )
          .max(20),
        truncated: z.boolean(),
      }),
    )
    .max(5_000),
  undocumented: z.array(shortText).max(5_000),
  unverified: z.array(shortText).max(5_000),
  unusedDeclarations: z.array(shortText).max(5_000),
  dynamicAccesses: z
    .array(
      z.object({
        file: shortText,
        line: z.number().int().positive(),
        syntax: z.enum(['process.env', 'import.meta.env']),
      }),
    )
    .max(100),
  summary: z.object({
    used: z.number().int().nonnegative().max(5_000),
    documented: z.number().int().nonnegative().max(5_000),
    undocumented: z.number().int().nonnegative().max(5_000),
    platformProvided: z.number().int().nonnegative().max(5_000),
    unverified: z.number().int().nonnegative().max(5_000),
    unusedDeclarations: z.number().int().nonnegative().max(5_000),
    dynamicAccesses: z.number().int().nonnegative().max(100),
  }),
  truncated: z.boolean(),
  limitations: z.array(shortText).max(20),
});

const testEvidence = z.object({
  schemaVersion: z.literal(1),
  version: shortText,
  status: z.enum(['complete', 'partial', 'unsupported']),
  testFiles: z.number().int().nonnegative(),
  criticalFiles: z.number().int().nonnegative(),
  withRelatedTests: z.number().int().nonnegative(),
  withoutRelatedTests: z.number().int().nonnegative(),
  targets: z
    .array(
      z.object({
        file: shortText,
        componentId: shortText.optional(),
        entrypointIds: z.array(shortText).max(100),
        sensitiveFactIds: z.array(shortText).max(100),
        sensitiveFactKinds: z.array(shortText).max(30),
        status: z.enum(['observed', 'not-observed']),
        relatedTests: z
          .array(
            z.object({
              file: shortText,
              relation: z.enum(['direct-import', 'transitive-import']),
              depth: z.number().int().positive().max(5),
            }),
          )
          .max(20),
        truncated: z.boolean(),
      }),
    )
    .max(500),
  parseFailures: z.number().int().nonnegative(),
  unresolvedImports: z.number().int().nonnegative(),
  truncated: z.boolean(),
  limitations: z.array(shortText).max(20),
});

const apiContract = z.object({
  schemaVersion: z.literal(1),
  version: shortText,
  status: z.enum(['complete', 'partial', 'unsupported']),
  specifications: z
    .array(
      z.object({
        file: shortText,
        version: shortText,
        operations: z.number().int().nonnegative().max(1_000),
        pathScope: shortText.optional(),
      }),
    )
    .max(20),
  declaredOperations: z
    .array(
      z.object({
        id: shortText,
        file: shortText,
        line: z.number().int().positive(),
        path: shortText,
        normalizedPath: shortText,
        method: shortText,
        operationId: shortText.optional(),
        entrypointIds: z.array(shortText).max(100),
        status: z.enum(['matched', 'declared-only']),
      }),
    )
    .max(1_000),
  sourceOperations: z
    .array(
      z.object({
        id: shortText,
        entrypointId: shortText,
        componentId: shortText.optional(),
        file: shortText,
        line: z.number().int().positive(),
        path: shortText,
        normalizedPath: shortText,
        method: shortText,
        contractOperationIds: z.array(shortText).max(100),
        status: z.enum(['matched', 'source-only', 'outside-contract-scope']),
      }),
    )
    .max(2_000),
  sourceRoutesWithoutMethods: z.array(shortText).max(500),
  summary: z.object({
    specifications: z.number().int().nonnegative().max(20),
    declaredOperations: z.number().int().nonnegative().max(1_000),
    matchedOperations: z.number().int().nonnegative().max(1_000),
    declaredOnly: z.number().int().nonnegative().max(1_000),
    sourceOperations: z.number().int().nonnegative().max(2_000),
    sourceOnly: z.number().int().nonnegative().max(2_000),
    outsideContractScope: z.number().int().nonnegative().max(2_000),
    sourceRoutesWithoutMethods: z.number().int().nonnegative().max(500),
  }),
  parseFailures: z.number().int().nonnegative().max(20),
  unresolvedPathReferences: z.number().int().nonnegative().max(1_000),
  truncated: z.boolean(),
  limitations: z.array(shortText).max(20),
});

const databaseContract = z.object({
  schemaVersion: z.literal(1),
  version: shortText,
  status: z.enum(['complete', 'partial', 'unsupported']),
  schemaFiles: z
    .array(
      z.object({
        file: shortText,
        kind: z.enum(['prisma', 'drizzle', 'sql']),
        entities: z.number().int().nonnegative().max(2_000),
      }),
    )
    .max(100),
  migrationFiles: z
    .array(
      z.object({
        file: shortText,
        references: z.number().int().nonnegative().max(2_000),
      }),
    )
    .max(500),
  entities: z
    .array(
      z.object({
        id: shortText,
        name: shortText,
        normalizedName: shortText,
        declarations: z
          .array(
            z.object({
              file: shortText,
              line: z.number().int().positive(),
              kind: z.enum(['prisma-model', 'drizzle-table', 'sql-table']),
              name: shortText,
            }),
          )
          .max(100),
        migrations: z
          .array(
            z.object({
              file: shortText,
              line: z.number().int().positive(),
              operation: z.enum(['create', 'alter', 'drop']),
              name: shortText,
            }),
          )
          .max(100),
        sourceReferences: z
          .array(
            z.object({
              file: shortText,
              line: z.number().int().positive(),
              signal: shortText,
            }),
          )
          .max(100),
        gaps: z
          .array(
            z.enum([
              'source-without-declaration',
              'declaration-without-create-migration',
              'migration-without-declaration',
            ]),
          )
          .max(3),
      }),
    )
    .max(2_000),
  summary: z.object({
    schemaFiles: z.number().int().nonnegative().max(100),
    migrationFiles: z.number().int().nonnegative().max(500),
    declaredEntities: z.number().int().nonnegative().max(2_000),
    migrationEntities: z.number().int().nonnegative().max(2_000),
    sourceEntities: z.number().int().nonnegative().max(2_000),
    linkedEntities: z.number().int().nonnegative().max(2_000),
    gapCandidates: z.number().int().nonnegative().max(2_000),
  }),
  parseFailures: z.number().int().nonnegative().max(100),
  truncated: z.boolean(),
  limitations: z.array(shortText).max(20),
});

const webhookContract = z.object({
  schemaVersion: z.literal(1),
  version: shortText,
  status: z.enum(['complete', 'partial', 'unsupported']),
  endpoints: z
    .array(
      z.object({
        id: shortText,
        entrypointId: shortText,
        file: shortText,
        line: z.number().int().positive(),
        route: shortText.optional(),
        methods: z.array(shortText).max(20),
        componentId: shortText.optional(),
        reachableSymbolIds: z.array(shortText).max(1_000),
        callEdgeIds: z.array(shortText).max(5_000),
        verificationEvidenceIds: z.array(shortText).max(100),
        idempotencyEvidenceIds: z.array(shortText).max(100),
        eventReferenceIds: z.array(shortText).max(2_000),
        verification: z.enum(['evidenced', 'unverified']),
        idempotency: z.enum(['evidenced', 'unverified']),
        traversalTruncated: z.boolean(),
      }),
    )
    .max(200),
  eventReferences: z
    .array(
      z.object({
        id: shortText,
        file: shortText,
        line: z.number().int().positive(),
        event: shortText,
        normalizedEvent: shortText,
        direction: z.enum(['produced', 'consumed']),
        origin: z.enum(['branch', 'return-contract', 'dispatch-call']),
        symbolId: shortText.optional(),
        componentId: shortText.optional(),
      }),
    )
    .max(2_000),
  events: z
    .array(
      z.object({
        id: shortText,
        event: shortText,
        normalizedEvent: shortText,
        producerReferenceIds: z.array(shortText).max(2_000),
        consumerReferenceIds: z.array(shortText).max(2_000),
        status: z.enum([
          'matched-local',
          'external-consumer-boundary',
          'external-producer-boundary',
        ]),
      }),
    )
    .max(2_000),
  summary: z.object({
    endpoints: z.number().int().nonnegative().max(200),
    verifiedEndpoints: z.number().int().nonnegative().max(200),
    idempotentEndpoints: z.number().int().nonnegative().max(200),
    producedEvents: z.number().int().nonnegative().max(2_000),
    consumedEvents: z.number().int().nonnegative().max(2_000),
    matchedEvents: z.number().int().nonnegative().max(2_000),
    externalConsumerBoundaries: z.number().int().nonnegative().max(2_000),
    externalProducerBoundaries: z.number().int().nonnegative().max(2_000),
  }),
  parseFailures: z.number().int().nonnegative().max(2_000),
  truncated: z.boolean(),
  limitations: z.array(shortText).max(20),
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
  schemaVersion: z.union([
    z.literal(1),
    z.literal(2),
    z.literal(3),
    z.literal(4),
    z.literal(5),
    z.literal(6),
    z.literal(7),
    z.literal(8),
    z.literal(9),
    z.literal(10),
    z.literal(11),
    z.literal(12),
  ]),
  auditId: shortText,
  projectName: shortText,
  createdAt: shortText,
  snapshotDigest: shortText,
  filesAnalyzed: z.number().int().nonnegative(),
  skipped: z.record(z.string(), z.number().int().nonnegative()),
  truncated: z.boolean(),
  aiMode: z.enum(['disabled', 'ollama', 'openai']),
  auditModes: z
    .array(
      z.object({
        id: z.enum([
          'security',
          'saas',
          'accessibility-static',
          'privacy',
          'reliability',
          'next-react',
          'maintainability',
          'release-readiness',
        ]),
        version: shortText,
        enabled: z.boolean(),
      }),
    )
    .max(8)
    .optional(),
  findings: z.array(finding).max(10_000),
  scanners: z.array(scanner).max(1_000),
  dependencies: z.array(dependency).max(100_000),
  scopePreflight: scopePreflight.optional(),
  projectProfile: projectProfile.optional(),
  riskCorrelation: riskCorrelation.optional(),
  environmentContract: environmentContract.optional(),
  testEvidence: testEvidence.optional(),
  apiContract: apiContract.optional(),
  databaseContract: databaseContract.optional(),
  webhookContract: webhookContract.optional(),
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
  reviewImport: z
    .object({
      schemaVersion: z.literal(1),
      ledgerDigest: z.string().regex(/^[a-f0-9]{64}$/),
      sourceAuditIds: z.array(shortText).max(10_000),
      importedAt: shortText,
      entries: z.number().int().nonnegative(),
      applied: z.number().int().nonnegative(),
      stale: z.number().int().nonnegative(),
      unmatched: z.number().int().nonnegative(),
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
  modes: z
    .array(
      z.enum([
        'security',
        'saas',
        'accessibility-static',
        'privacy',
        'reliability',
        'next-react',
        'maintainability',
        'release-readiness',
      ]),
    )
    .max(8)
    .optional(),
  scopePreflight: scopePreflight.optional(),
});

export function parseAuditReport(value: unknown): AuditReport {
  return auditReportSchema.parse(value) as AuditReport;
}

export function parseStoredAuditOptions(value: unknown): AuditOptions {
  return storedOptionsSchema.parse(value) as AuditOptions;
}
