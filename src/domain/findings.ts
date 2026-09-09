import { createHash } from 'node:crypto';
import type { Evidence, Finding, Severity } from './types.ts';
import { redact } from '../security/redact.ts';
export function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
export function makeFinding(input: Omit<Finding, 'id' | 'fingerprint' | 'disposition'>): Finding {
  const location = input.evidence[0];
  const fingerprint = digest([input.source, input.ruleId, location?.file, location?.startLine].join(':'));
  return { ...input, id: fingerprint.slice(0, 20), fingerprint, disposition: 'needs_review' };
}
export function mergeFindings(left: Finding[], right: Finding[]): Finding[] {
  const records = new Map(left.map((finding) => [finding.fingerprint, finding]));
  for (const finding of right)
    records.set(finding.fingerprint, finding);
  return [...records.values()].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id));
}
export function severityRank(severity: Severity): number {
  return ['critical', 'high', 'medium', 'low', 'info'].indexOf(severity);
}
export function sourceEvidence(file: {
  path: string;
  content: string;
  digest: string;
}, line: number, observation: string): Evidence {
  const lines = file.content.split('\n');
  if (!Number.isSafeInteger(line) || line < 1 || line > lines.length) throw new Error('Evidence location is outside the captured source.');
  const startLine = Math.max(1, line - 2);
  const endLine = Math.min(lines.length, line + 3);
  return {
    id: digest(`${file.path}:${line}:${observation}`).slice(0, 16),
    file: file.path, startLine, endLine,
    excerpt: redact(lines.slice(startLine - 1, endLine).join('\n')).slice(0, 2200),
    fileDigest: file.digest, observation,
  };
}
