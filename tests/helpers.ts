import { digest } from '../src/domain/findings.ts';
import { scanPatterns } from '../src/scanners/builtin.ts';
import type { AuditReport, Snapshot } from '../src/domain/types.ts';
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
