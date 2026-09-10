import { digest } from '../src/domain/findings.ts';
import { scanPatterns } from '../src/scanners/builtin.ts';
import type {
  AuditReport,
  EnvironmentContractAnalysis,
  RiskCorrelation,
  Snapshot,
} from '../src/domain/types.ts';
export function snapshotOf(content: string, file = 'src/example.ts'): Snapshot {
  return {
    digest: digest(content),
    files: [
      {
        path: file,
        scope: 'runtime',
        content,
        digest: digest(content),
        bytes: Buffer.byteLength(content),
      },
    ],
    totalBytes: Buffer.byteLength(content),
    skipped: {},
    truncated: false,
  };
}
export function snapshotFromFiles(files: Record<string, string>): Snapshot {
  const sourceFiles = Object.entries(files).map(([path, content]) => ({
    path,
    scope: 'runtime' as const,
    content,
    digest: digest(content),
    bytes: Buffer.byteLength(content),
  }));
  return {
    digest: digest(sourceFiles.map((file) => `${file.path}:${file.digest}`).join('\n')),
    files: sourceFiles,
    totalBytes: sourceFiles.reduce((total, file) => total + file.bytes, 0),
    skipped: {},
    truncated: false,
  };
}
export function sampleReport(): AuditReport {
  const source = snapshotOf('export const result = eval(input);');
  return {
    schemaVersion: 1,
    auditId: '00000000-0000-4000-8000-000000000001',
    projectName: 'sample',
    createdAt: '2026-09-08T12:00:00.000Z',
    snapshotDigest: source.digest,
    filesAnalyzed: 1,
    skipped: {},
    truncated: false,
    aiMode: 'disabled',
    findings: scanPatterns(source),
    scanners: [
      {
        id: 'builtin',
        name: 'Patterns',
        status: 'completed',
        durationMs: 1,
        findings: 1,
        detail: 'Pattern-only review',
      },
    ],
    dependencies: [],
    limitations: ['Not a security certification.'],
    publication: 'draft',
  };
}

export function sampleRiskCorrelation(findingId: string): RiskCorrelation {
  return {
    schemaVersion: 1,
    version: '1.0.0',
    status: 'complete',
    paths: [
      {
        id: 'risk-path-1',
        entrypointId: 'entrypoint-1',
        route: '/api/example',
        methods: ['POST'],
        factId: 'fact-1',
        factKind: 'database',
        findingIds: [findingId],
        priority: 80,
        confidence: 'high',
        steps: [
          {
            kind: 'entrypoint',
            referenceId: 'entrypoint-1',
            file: 'src/app/api/example/route.ts',
            line: 1,
            label: '/api/example',
          },
          {
            kind: 'sensitive-operation',
            referenceId: 'fact-1',
            file: 'src/lib/database.ts',
            line: 8,
            label: 'database: account.update',
          },
        ],
        truncated: false,
      },
    ],
    summary: {
      paths: 1,
      entrypoints: 1,
      eligibleFindings: 1,
      correlatedFindings: 1,
      uncorrelatedFindings: 0,
      factKinds: { database: 1 },
    },
    truncated: false,
    limitations: ['Static source path only.'],
  };
}

export function sampleEnvironmentContract(): EnvironmentContractAnalysis {
  return {
    schemaVersion: 1,
    version: '1.0.0',
    status: 'complete',
    templates: [{ file: '.env.example', variables: 1 }],
    variables: [
      {
        name: 'WEBHOOK_SECRET',
        status: 'undocumented',
        declaredIn: [],
        locations: [
          {
            file: 'src/config.ts',
            line: 4,
            syntax: 'process.env',
            context: 'server',
          },
        ],
        truncated: false,
      },
    ],
    undocumented: ['WEBHOOK_SECRET'],
    unverified: [],
    unusedDeclarations: ['OLD_SETTING'],
    dynamicAccesses: [],
    summary: {
      used: 1,
      documented: 0,
      undocumented: 1,
      platformProvided: 0,
      unverified: 0,
      unusedDeclarations: 1,
      dynamicAccesses: 0,
    },
    truncated: false,
    limitations: ['Deployment-provided names remain possible.'],
  };
}
