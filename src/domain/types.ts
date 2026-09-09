export const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof severities)[number];
export type Category = 'authorization' | 'injection' | 'secrets' | 'configuration' | 'ai-security' | 'dependencies' | 'code';
export type Disposition = 'needs_review' | 'confirmed' | 'false_positive' | 'accepted_risk';
export type AuditStatus = 'queued' | 'running' | 'awaiting_review' | 'completed' | 'failed' | 'cancelled';
export type ScannerStatus = 'completed' | 'partial' | 'skipped' | 'failed';
export interface SourceFile {
  path: string;
  content: string;
  digest: string;
  bytes: number;
}
export interface Snapshot {
  digest: string;
  files: SourceFile[];
  totalBytes: number;
  skipped: Record<string, number>;
  truncated: boolean;
}
export interface Evidence {
  id: string;
  file: string;
  startLine: number;
  endLine: number;
  excerpt: string;
  fileDigest: string;
  observation: string;
}
export interface Analysis {
  kind: 'deterministic' | 'ollama';
  assessment: 'needs_review' | 'likely_issue' | 'likely_false_positive' | 'inconclusive';
  explanation: string;
  evidenceIds: string[];
  limitations: string[];
  inspectedFiles: string[];
  rounds: number;
}
export interface Finding {
  id: string;
  fingerprint: string;
  ruleId: string;
  source: 'builtin' | 'semgrep' | 'gitleaks';
  title: string;
  category: Category;
  severity: Severity;
  sourceSeverity: string;
  description: string;
  remediation: string;
  cwe: string[];
  evidence: Evidence[];
  disposition: Disposition;
  analysis?: Analysis;
  review?: {
    decision: Disposition;
    note: string;
    at: string;
  };
}
export interface ScannerRun {
  id: string;
  name: string;
  status: ScannerStatus;
  durationMs: number;
  findings: number;
  detail: string;
  version?: string;
}
export interface Dependency {
  name: string;
  requestedVersion: string;
  manifest: string;
  scope: 'runtime' | 'development';
}
export interface Project {
  id: string;
  name: string;
  root: string;
  createdAt: string;
}
export interface AuditEvent {
  id: number;
  auditId: string;
  stage: string;
  message: string;
  at: string;
}
export interface AuditReport {
  schemaVersion: 1;
  auditId: string;
  projectName: string;
  createdAt: string;
  snapshotDigest: string;
  filesAnalyzed: number;
  skipped: Record<string, number>;
  truncated: boolean;
  aiMode: 'disabled' | 'ollama';
  findings: Finding[];
  scanners: ScannerRun[];
  dependencies: Dependency[];
  limitations: string[];
  publication: 'draft' | 'reviewed';
  reviewNote?: string;
}
export interface Audit {
  id: string;
  projectId: string;
  projectName: string;
  status: AuditStatus;
  createdAt: string;
  updatedAt: string;
  error: string | null;
  report: AuditReport | null;
  resumeNote: string | null;
  attempts: number;
}
export interface ReviewDecision {
  findingId: string;
  disposition: Disposition;
  note: string;
}
