export const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof severities)[number];
export type Category =
  | 'authentication'
  | 'authorization'
  | 'injection'
  | 'secrets'
  | 'configuration'
  | 'ai-security'
  | 'dependencies'
  | 'code';
export type Disposition = 'needs_review' | 'confirmed' | 'false_positive' | 'accepted_risk';
export type AuditStatus =
  'queued' | 'running' | 'awaiting_review' | 'completed' | 'failed' | 'cancelled';
export type ScannerStatus = 'completed' | 'partial' | 'skipped' | 'failed';
export type CoverageStatus =
  'COMPLETE' | 'PARTIAL' | 'FAILED' | 'NOT RUN' | 'DISABLED' | 'NOT SUPPORTED' | 'NOT PERFORMED';
export interface CoverageCapability {
  id: string;
  label: string;
  status: CoverageStatus;
  detail: string;
  findings?: number;
  version?: string;
}
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
  kind?: 'source' | 'declared' | 'observed' | 'dependency' | 'inferred';
  file: string;
  startLine: number;
  endLine: number;
  excerpt: string;
  fileDigest: string;
  observation: string;
  url?: string;
  observedAt?: string;
}
export interface Analysis {
  kind: 'deterministic' | 'ollama' | 'openai';
  assessment: 'needs_review' | 'likely_issue' | 'likely_false_positive' | 'inconclusive';
  explanation: string;
  evidenceIds: string[];
  limitations: string[];
  controlsFound?: string[];
  missingEvidence?: string[];
  impact?: string;
  preconditions?: string[];
  remediationOptions?: string[];
  verificationPlan?: string[];
  inspectedFiles: string[];
  rounds: number;
  confidence?: 'low' | 'medium' | 'high';
  provider?: 'ollama' | 'openai';
  model?: string;
  promptVersion?: string;
  contextFilesSent?: string[];
  contextIdsSent?: string[];
  contextCharactersSent?: number;
  contextTruncated?: boolean;
  redactionApplied?: boolean;
  cached?: boolean;
  tokenUsage?: {
    inputTokens: number;
    outputTokens: number;
    cachedInputTokens?: number;
  };
  approximateCostUsd?: number;
}
export interface AiUsage {
  provider: 'ollama' | 'openai';
  models: string[];
  calls: number;
  cacheHits: number;
  inputTokens: number;
  outputTokens: number;
  approximateCostUsd?: number;
  contextFilesSent: string[];
  contextIdsSent: string[];
  redactionApplied: boolean;
}
export interface Finding {
  id: string;
  fingerprint: string;
  ruleId: string;
  source: 'builtin' | 'posture' | 'ast' | 'http-probe' | 'osv' | 'semgrep' | 'gitleaks';
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
  runtimeVerification?: {
    status: 'corroborated' | 'observed_safe' | 'different';
    observation: string;
    url: string;
    observedAt: string;
  };
  vulnerability?: {
    id: string;
    aliases: string[];
    package: string;
    version: string;
    fixedVersions: string[];
    severity: { type: string; score: string }[];
    relationship: 'direct' | 'transitive' | 'unknown';
    lockfile: string;
    advisoryModified?: string;
  };
  provenance?: {
    detector:
      'traceward-heuristic' | 'traceward-ast' | 'scanner' | 'runtime-probe' | 'advisory-database';
    scanner: string;
    ruleId: string;
    scannerVersion?: string;
    originalSeverity: string;
    detectedAt: string;
    evidenceKinds: ('source' | 'declared' | 'observed' | 'dependency' | 'inferred')[];
  };
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
  resolvedVersion?: string;
  manifest: string;
  scope: 'runtime' | 'development';
  relationship?: 'direct' | 'transitive' | 'unknown';
  lockfile?: string;
  lockfileLine?: number;
}
export interface HttpProbeOptions {
  url: string;
  allowPrivateNetwork: boolean;
}
export interface AuditOptions {
  httpProbe?: HttpProbeOptions;
}
export interface HttpProbeReport {
  requestedUrl: string;
  finalUrl: string;
  method: 'HEAD' | 'GET';
  statusCode: number;
  redirects: number;
  observedAt: string;
  durationMs: number;
  headers: Record<string, string>;
  cookies: {
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'strict' | 'lax' | 'none' | 'unspecified';
  }[];
}
export type ProjectProfileStatus = 'complete' | 'partial' | 'unsupported';
export type ProjectEntrypointKind =
  'next-route' | 'next-pages-api' | 'server-action' | 'middleware' | 'express-route';
export type ProjectFactKind =
  | 'authentication'
  | 'authorization'
  | 'validation'
  | 'database'
  | 'raw-sql'
  | 'outbound-request'
  | 'command-execution'
  | 'file-access'
  | 'redirect'
  | 'cookie'
  | 'response'
  | 'secret-access'
  | 'resource-scope'
  | 'logging'
  | 'error-handling'
  | 'webhook-verification';
export interface ProjectFramework {
  id: 'nextjs-app-router' | 'nextjs-pages-router' | 'express' | 'prisma' | 'supabase';
  name: string;
  file: string;
  line: number;
}
export interface ProjectEntrypoint {
  id: string;
  kind: ProjectEntrypointKind;
  file: string;
  line: number;
  name: string;
  route?: string;
  methods: string[];
  dynamicParameters: string[];
  symbolIds: string[];
}
export interface ProjectSymbol {
  id: string;
  file: string;
  line: number;
  name: string;
  kind: 'function' | 'arrow-function' | 'method';
  exported: boolean;
}
export interface ProjectImportBinding {
  imported: string;
  local: string;
}
export interface ProjectImport {
  id: string;
  file: string;
  line: number;
  specifier: string;
  bindings: ProjectImportBinding[];
  resolvedFile?: string;
}
export interface ProjectCallEdge {
  id: string;
  file: string;
  line: number;
  callee: string;
  callerSymbolId?: string;
  targetSymbolId?: string;
}
export interface ProjectFact {
  id: string;
  kind: ProjectFactKind;
  file: string;
  line: number;
  signal: string;
  ownerSymbolId?: string;
}
export interface ProjectProfile {
  schemaVersion: 1;
  status: ProjectProfileStatus;
  languages: ('typescript' | 'javascript')[];
  frameworks: ProjectFramework[];
  entrypoints: ProjectEntrypoint[];
  symbols: ProjectSymbol[];
  imports: ProjectImport[];
  calls: ProjectCallEdge[];
  facts: ProjectFact[];
  filesAnalyzed: number;
  nodesAnalyzed: number;
  issues: string[];
  truncated: boolean;
}
export type SecurityControlStatus =
  'EVIDENCED' | 'GAP_CANDIDATE' | 'UNVERIFIED' | 'NOT_APPLICABLE' | 'PARTIAL' | 'FAILED';
export type SecurityControlDomain =
  | 'authentication'
  | 'authorization'
  | 'input-validation'
  | 'browser-security'
  | 'secrets'
  | 'dependencies'
  | 'runtime'
  | 'logging'
  | 'integrations';
export interface SecurityControlEvidenceRef {
  kind: 'finding' | 'profile-fact' | 'scanner' | 'http-observation';
  id: string;
}
export interface SecurityControlResult {
  id: string;
  domain: SecurityControlDomain;
  title: string;
  status: SecurityControlStatus;
  rationale: string;
  applicability: string;
  evidence: SecurityControlEvidenceRef[];
  verification: string;
  limitations: string[];
}
export interface SecurityChecklist {
  schemaVersion: 1;
  packId: 'traceward-web-application';
  packVersion: string;
  controls: SecurityControlResult[];
  summary: Record<SecurityControlStatus, number>;
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
  schemaVersion: 1 | 2 | 3;
  auditId: string;
  projectName: string;
  createdAt: string;
  snapshotDigest: string;
  filesAnalyzed: number;
  skipped: Record<string, number>;
  truncated: boolean;
  aiMode: 'disabled' | 'ollama' | 'openai';
  findings: Finding[];
  scanners: ScannerRun[];
  dependencies: Dependency[];
  projectProfile?: ProjectProfile;
  checklist?: SecurityChecklist;
  httpProbe?: HttpProbeReport;
  coverage?: CoverageCapability[];
  aiUsage?: AiUsage;
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
  options: AuditOptions;
}
export interface ReviewDecision {
  findingId: string;
  disposition: Disposition;
  note: string;
}
export interface FindingReference {
  id: string;
  fingerprint: string;
  ruleId: string;
  title: string;
  severity: Severity;
}
export interface AuditComparison {
  baseAuditId: string;
  currentAuditId: string;
  newFindings: FindingReference[];
  resolvedFindings: FindingReference[];
  unchangedFindings: FindingReference[];
  severityChanges: {
    finding: FindingReference;
    before: Severity;
    after: Severity;
  }[];
}
