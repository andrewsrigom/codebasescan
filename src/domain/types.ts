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
export type Disposition =
  'needs_review' | 'confirmed' | 'fixed' | 'false_positive' | 'accepted_risk';
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
export type SourceScope = 'runtime' | 'test' | 'example';
export interface SourceFile {
  path: string;
  scope: SourceScope;
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
  kind?: 'source' | 'declared' | 'observed' | 'dependency' | 'inferred' | 'history';
  scope?: SourceScope;
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
  contextIdsSent?: string[];
  redactionApplied: boolean;
}
export interface Finding {
  id: string;
  fingerprint: string;
  ruleId: string;
  source:
    | 'builtin'
    | 'posture'
    | 'ast'
    | 'saas'
    | 'next'
    | 'react'
    | 'supply-chain'
    | 'http-probe'
    | 'osv'
    | 'semgrep'
    | 'gitleaks';
  title: string;
  category: Category;
  severity: Severity;
  sourceSeverity: string;
  description: string;
  remediation: string;
  cwe: string[];
  evidence: Evidence[];
  disposition: Disposition;
  confidence?: 'low' | 'medium' | 'high';
  exposure?: 'potentially_public' | 'authenticated' | 'local' | 'unknown';
  priority?: number;
  suppression?: {
    reason: string;
    createdAt: string;
    expiresAt?: string;
  };
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
    reachability: 'referenced' | 'not_found' | 'unknown';
    lockfile: string;
    advisoryModified?: string;
  };
  secret?: {
    classification: 'probable' | 'fixture_candidate' | 'historical';
    commit?: string;
  };
  provenance?: {
    detector:
      'traceward-heuristic' | 'traceward-ast' | 'scanner' | 'runtime-probe' | 'advisory-database';
    scanner: string;
    ruleId: string;
    scannerVersion?: string;
    originalSeverity: string;
    detectedAt: string;
    evidenceKinds: ('source' | 'declared' | 'observed' | 'dependency' | 'inferred' | 'history')[];
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
  parentChains?: string[][];
}
export interface HttpProbeOptions {
  url: string;
  allowPrivateNetwork: boolean;
}
export interface ProjectScopeEstimate {
  schemaVersion: 1;
  estimatedAt: string;
  supportedFiles: number;
  supportedBytes: number;
  scopeFiles?: Record<SourceScope, number>;
  oversizedFiles: number;
  visitedEntries: number;
  predictedTruncated: boolean;
  reasons: string[];
  limits: {
    files: number;
    bytesPerFile: number;
    lockfileBytes?: number;
    totalBytes: number;
  };
}
export interface AuditScopePreflight extends ProjectScopeEstimate {
  truncationApproved: boolean;
}
export interface AuditOptions {
  httpProbe?: HttpProbeOptions;
  gitHistorySecrets?: boolean;
  scopePreflight?: AuditScopePreflight;
}
export interface HttpProbeReport {
  requestedUrl: string;
  finalUrl: string;
  method: 'HEAD' | 'GET';
  statusCode: number;
  redirects: number;
  redirectChain?: {
    statusCode: number;
    from: string;
    to: string;
  }[];
  probeOrigin?: string;
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
  | 'next-route'
  | 'next-pages-api'
  | 'server-action'
  | 'middleware'
  | 'express-route'
  | 'trpc-procedure';
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
  | 'webhook-verification'
  | 'rate-limit'
  | 'idempotency'
  | 'csrf';
export interface ProjectFramework {
  id:
    | 'nextjs-app-router'
    | 'nextjs-pages-router'
    | 'express'
    | 'prisma'
    | 'drizzle'
    | 'supabase'
    | 'authjs'
    | 'trpc'
    | 'graphql'
    | 'zod'
    | 'joi'
    | 'valibot';
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
  matchers?: string[];
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
export interface ProjectSaasSemantics {
  schemaVersion: 1;
  sources: string[];
  vocabulary: {
    tenantKeys: string[];
    ownerKeys: string[];
    roleKeys: string[];
    billingKeys: string[];
    tokenKeys: string[];
  };
  helpers: {
    authentication: string[];
    authorization: string[];
    validation: string[];
    resourceScope: string[];
    rateLimit: string[];
    idempotency: string[];
    csrf: string[];
    auditLog: string[];
  };
  expectedUnauthenticatedRoutes: string[];
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
  saasSemantics?: ProjectSaasSemantics;
  filesAnalyzed: number;
  nodesAnalyzed: number;
  issues: string[];
  truncated: boolean;
}
export interface ArchitectureHotspot {
  file: string;
  incoming: number;
  outgoing: number;
  instability: number;
}
export interface ArchitectureCycle {
  id: string;
  files: string[];
}
export interface ArchitectureAnalysis {
  schemaVersion: 1;
  modules: number;
  localDependencies: number;
  cycleCount?: number;
  cycles: ArchitectureCycle[];
  orphanCount?: number;
  orphanCandidates: string[];
  hotspotCount?: number;
  hotspots: ArchitectureHotspot[];
  truncated: boolean;
}
export interface DuplicateLocation {
  file: string;
  startLine: number;
  endLine: number;
}
export interface DuplicateBlock {
  id: string;
  kind: 'exact' | 'similar';
  format: string;
  lines: number;
  tokens: number;
  first: DuplicateLocation;
  second: DuplicateLocation;
}
export interface DuplicationAnalysis {
  schemaVersion: 1;
  files: number;
  lines: number;
  tokens: number;
  clones: number;
  duplicatedLines: number;
  percentage: number;
  blocks: DuplicateBlock[];
  truncated: boolean;
}
export interface MechanicalAnalysis {
  schemaVersion: 1;
  architecture?: ArchitectureAnalysis;
  duplication?: DuplicationAnalysis;
}
export interface SupplyChainAnalysis {
  schemaVersion: 1;
  manifests: number;
  lockfiles: number;
  lifecycleScripts: number;
  dependencySpecs: number;
  lockEntries: number;
  issueCounts: {
    dangerousLifecycleScripts: number;
    unsafeDependencySpecs: number;
    weakLockfileIntegrity: number;
    insecureLockfileUrls: number;
    unexpectedLockfileHosts: number;
    manifestLockMismatches: number;
  };
  truncated: boolean;
}
export interface FunctionHotspot {
  file: string;
  line: number;
  name: string;
  lines: number;
  parameters: number;
  complexity: number;
}
export interface DeadCodeSymbol {
  file: string;
  line: number;
  name: string;
}
export interface DeadCodeAnalysis {
  schemaVersion: 1;
  unusedFileCount?: number;
  unusedFiles: string[];
  unusedDependencyCount?: number;
  unusedDependencies: string[];
  unlistedDependencyCount?: number;
  unlistedDependencies: DeadCodeSymbol[];
  unusedExportCount?: number;
  unusedExports: DeadCodeSymbol[];
  unusedTypeCount?: number;
  unusedTypes: DeadCodeSymbol[];
  truncated: boolean;
}
export interface CoverageArtifactSummary {
  file: string;
  lines?: number;
  statements?: number;
  functions?: number;
  branches?: number;
}
export interface CodeQualityAnalysis {
  schemaVersion: 1;
  filesAnalyzed: number;
  functionsAnalyzed: number;
  hotspotCount?: number;
  hotspots: FunctionHotspot[];
  deadCode?: DeadCodeAnalysis;
  coverageArtifacts: CoverageArtifactSummary[];
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
export type SecurityControlReviewDecision =
  'verified_external' | 'accepted_gap' | 'not_applicable' | 'needs_follow_up';
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
  review?: {
    decision: SecurityControlReviewDecision;
    note: string;
    at: string;
  };
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
  baselineAuditId?: string;
}
export interface AuditEvent {
  id: number;
  auditId: string;
  stage: string;
  message: string;
  at: string;
}
export interface AuditReport {
  schemaVersion: 1 | 2 | 3 | 4 | 5;
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
  scopePreflight?: AuditScopePreflight;
  projectProfile?: ProjectProfile;
  mechanicalAnalysis?: MechanicalAnalysis;
  supplyChainAnalysis?: SupplyChainAnalysis;
  codeQualityAnalysis?: CodeQualityAnalysis;
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
  workflowVersion: string;
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
export interface SuppressionDecision {
  findingId: string;
  reason: string;
  expiresAt?: string;
}
export interface ControlReviewDecision {
  controlId: string;
  decision: SecurityControlReviewDecision;
  note: string;
}
export interface FindingReference {
  id: string;
  fingerprint: string;
  ruleId: string;
  title: string;
  severity: Severity;
  suppressed?: boolean;
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
