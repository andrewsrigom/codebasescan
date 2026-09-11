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
  | 'accessibility'
  | 'privacy'
  | 'reliability'
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
  focusLine?: number;
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
    | 'accessibility'
    | 'axe'
    | 'web'
    | 'privacy'
    | 'reliability'
    | 'environment'
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
    owner?: string;
    evidence?: string;
    createdAt: string;
    expiresAt?: string;
    source?: 'local-project' | 'portable-ledger';
    target?: {
      fingerprint: string;
      ruleId: string;
      paths: string[];
    };
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
      | 'codebasescan-heuristic'
      | 'codebasescan-ast'
      | 'scanner'
      | 'runtime-probe'
      | 'advisory-database';
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
  cache?: {
    status: 'hit' | 'miss';
    key: string;
    storedAt?: string;
    sourceDurationMs?: number;
  };
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
export const auditModes = [
  'security',
  'saas',
  'accessibility-static',
  'privacy',
  'reliability',
  'next-react',
  'maintainability',
  'release-readiness',
  'web-posture',
] as const;
export type AuditMode = (typeof auditModes)[number];
export interface AuditModeSelection {
  id: AuditMode;
  version: string;
  enabled: boolean;
}
export interface AuditOptions {
  httpProbe?: HttpProbeOptions;
  gitHistorySecrets?: boolean;
  modes?: AuditMode[];
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
  htmlSurface?: {
    contentType: string;
    bodyTruncated: boolean;
    formsObserved: number;
    formsRetained: number;
    formEndpoints: {
      method: 'GET' | 'POST' | 'DIALOG' | 'UNKNOWN';
      action: string;
      relationship: 'same-origin' | 'cross-origin' | 'unresolved';
      hasPassword: boolean;
    }[];
  };
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
  | 'billing'
  | 'raw-sql'
  | 'outbound-request'
  | 'command-execution'
  | 'file-access'
  | 'redirect'
  | 'cookie'
  | 'browser-storage'
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
    | 'react'
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
  componentId?: string;
  versionCoverage?: {
    requested?: string;
    detectedMajor?: number;
    status: 'supported' | 'partial' | 'unverified';
    supportedMajors?: number[];
    detail: string;
  };
}
export interface ProjectComponent {
  id: string;
  name: string;
  root: string;
  manifest: string;
  kind: 'root' | 'package';
  private?: boolean;
  sourceFiles: number;
}
export interface ProjectComponentEdge {
  id: string;
  fromComponentId: string;
  toComponentId: string;
  imports: number;
  importIds: string[];
  truncated: boolean;
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
  componentId?: string;
}
export interface ProjectSymbol {
  id: string;
  file: string;
  line: number;
  endLine?: number;
  name: string;
  kind: 'function' | 'arrow-function' | 'method';
  exported: boolean;
  componentId?: string;
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
  componentId?: string;
}
export interface ProjectCallEdge {
  id: string;
  file: string;
  line: number;
  callee: string;
  callerSymbolId?: string;
  targetSymbolId?: string;
  componentId?: string;
}
export interface ProjectFact {
  id: string;
  kind: ProjectFactKind;
  file: string;
  line: number;
  signal: string;
  ownerSymbolId?: string;
  componentId?: string;
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
  context?: ProjectDeclaredContext;
  verification?: ProjectVerificationContext;
}
export type ProjectFeature =
  'authentication' | 'tenancy' | 'billing' | 'webhooks' | 'administration' | 'uploads';
export type ProjectSensitiveDataClass =
  | 'credentials'
  | 'personal'
  | 'financial'
  | 'health'
  | 'location'
  | 'communications'
  | 'files'
  | 'analytics';
export interface ProjectDeclaredContext {
  features: ProjectFeature[];
  roles: string[];
  sensitiveData: ProjectSensitiveDataClass[];
  storageBoundaries: string[];
  externalServices: string[];
  priorityPaths: string[];
  outOfScopePaths: string[];
}
export interface ProjectVerificationContext {
  packageManager: 'npm' | 'pnpm' | 'yarn';
  testScripts: string[];
  buildScripts: string[];
}
export type ProjectDataOperation =
  | 'sensitive-read'
  | 'persistent-storage'
  | 'browser-storage'
  | 'cookie'
  | 'response'
  | 'log'
  | 'url-or-redirect'
  | 'outbound-transfer'
  | 'financial-operation';
export interface ProjectDataMapEntry {
  id: string;
  operation: ProjectDataOperation;
  file: string;
  line: number;
  signal: string;
  sourceFactId: string;
  provenance: 'observed';
  dataClasses: (ProjectSensitiveDataClass | 'unknown')[];
}
export interface ProjectDataMap {
  schemaVersion: 1;
  entries: ProjectDataMapEntry[];
  summary: Partial<Record<ProjectDataOperation, number>>;
  declaredData: ProjectSensitiveDataClass[];
  declaredBoundaries: {
    storage: string[];
    externalServices: string[];
  };
  truncated: boolean;
}
export interface ProjectProfile {
  schemaVersion: 1;
  status: ProjectProfileStatus;
  languages: ('typescript' | 'javascript')[];
  frameworks: ProjectFramework[];
  components?: ProjectComponent[];
  componentEdges?: ProjectComponentEdge[];
  entrypoints: ProjectEntrypoint[];
  symbols: ProjectSymbol[];
  imports: ProjectImport[];
  calls: ProjectCallEdge[];
  facts: ProjectFact[];
  saasSemantics?: ProjectSaasSemantics;
  dataMap?: ProjectDataMap;
  filesAnalyzed: number;
  nodesAnalyzed: number;
  issues: string[];
  truncated: boolean;
}
export interface ProjectEntrypointPresentation extends ProjectEntrypoint {
  factKinds: ProjectFactKind[];
  sensitiveOperations: number;
}
export interface ProjectProfilePresentation {
  status: ProjectProfileStatus;
  languages: ProjectProfile['languages'];
  frameworks: ProjectFramework[];
  components: ProjectComponent[];
  componentEdges: ProjectComponentEdge[];
  entrypoints: ProjectEntrypointPresentation[];
  symbolCount: number;
  callCount: number;
  factCount: number;
  factCounts: [ProjectFactKind, number][];
  filesAnalyzed: number;
  nodesAnalyzed: number;
  issues: string[];
  truncated: boolean;
}
export type SourceRiskPathStepKind = 'entrypoint' | 'call' | 'sensitive-operation';
export interface SourceRiskPathStep {
  kind: SourceRiskPathStepKind;
  referenceId: string;
  file: string;
  line: number;
  label: string;
}
export interface SourceRiskPath {
  id: string;
  entrypointId: string;
  route?: string;
  methods: string[];
  factId: string;
  factKind: ProjectFactKind;
  findingIds: string[];
  priority: number;
  confidence: 'high';
  steps: SourceRiskPathStep[];
  truncated: boolean;
}
export interface RiskCorrelation {
  schemaVersion: 1;
  version: string;
  status: ProjectProfileStatus;
  paths: SourceRiskPath[];
  summary: {
    paths: number;
    entrypoints: number;
    eligibleFindings: number;
    correlatedFindings: number;
    uncorrelatedFindings: number;
    factKinds: Partial<Record<ProjectFactKind, number>>;
  };
  truncated: boolean;
  limitations: string[];
}
export interface EnvironmentContractLocation {
  file: string;
  line: number;
  syntax: 'process.env' | 'import.meta.env';
  context: 'server' | 'client';
}
export interface EnvironmentContractVariable {
  name: string;
  status: 'documented' | 'undocumented' | 'platform-provided' | 'unverified';
  declaredIn: string[];
  locations: EnvironmentContractLocation[];
  truncated: boolean;
}
export interface EnvironmentDynamicAccess {
  file: string;
  line: number;
  syntax: 'process.env' | 'import.meta.env';
}
export interface EnvironmentContractAnalysis {
  schemaVersion: 1;
  version: string;
  status: ProjectProfileStatus;
  templates: { file: string; variables: number }[];
  variables: EnvironmentContractVariable[];
  undocumented: string[];
  unverified: string[];
  unusedDeclarations: string[];
  dynamicAccesses: EnvironmentDynamicAccess[];
  summary: {
    used: number;
    documented: number;
    undocumented: number;
    platformProvided: number;
    unverified: number;
    unusedDeclarations: number;
    dynamicAccesses: number;
  };
  truncated: boolean;
  limitations: string[];
}

export interface TestEvidenceReference {
  file: string;
  relation: 'direct-import' | 'transitive-import';
  depth: number;
}
export interface TestEvidenceTarget {
  file: string;
  componentId?: string;
  entrypointIds: string[];
  sensitiveFactIds: string[];
  sensitiveFactKinds: ProjectFactKind[];
  status: 'observed' | 'not-observed';
  relatedTests: TestEvidenceReference[];
  truncated: boolean;
}
export interface TestEvidenceAnalysis {
  schemaVersion: 1;
  version: string;
  status: ProjectProfileStatus;
  testFiles: number;
  criticalFiles: number;
  withRelatedTests: number;
  withoutRelatedTests: number;
  targets: TestEvidenceTarget[];
  parseFailures: number;
  unresolvedImports: number;
  truncated: boolean;
  limitations: string[];
}
export interface ApiContractSpecification {
  file: string;
  version: string;
  operations: number;
  pathScope?: string;
}
export interface ApiContractOperation {
  id: string;
  file: string;
  line: number;
  path: string;
  normalizedPath: string;
  method: string;
  operationId?: string;
  entrypointIds: string[];
  status: 'matched' | 'declared-only';
}
export interface ApiSourceOperation {
  id: string;
  entrypointId: string;
  componentId?: string;
  file: string;
  line: number;
  path: string;
  normalizedPath: string;
  method: string;
  contractOperationIds: string[];
  status: 'matched' | 'source-only' | 'outside-contract-scope';
}
export interface ApiContractAnalysis {
  schemaVersion: 1;
  version: string;
  status: ProjectProfileStatus;
  specifications: ApiContractSpecification[];
  declaredOperations: ApiContractOperation[];
  sourceOperations: ApiSourceOperation[];
  sourceRoutesWithoutMethods: string[];
  summary: {
    specifications: number;
    declaredOperations: number;
    matchedOperations: number;
    declaredOnly: number;
    sourceOperations: number;
    sourceOnly: number;
    outsideContractScope: number;
    sourceRoutesWithoutMethods: number;
  };
  parseFailures: number;
  unresolvedPathReferences: number;
  truncated: boolean;
  limitations: string[];
}
export interface DatabaseContractLocation {
  file: string;
  line: number;
  kind: 'prisma-model' | 'drizzle-table' | 'sql-table';
  name: string;
}
export interface DatabaseMigrationReference {
  file: string;
  line: number;
  operation: 'create' | 'alter' | 'drop';
  name: string;
}
export interface DatabaseSourceReference {
  file: string;
  line: number;
  signal: string;
}
export interface DatabaseContractEntity {
  id: string;
  name: string;
  normalizedName: string;
  declarations: DatabaseContractLocation[];
  migrations: DatabaseMigrationReference[];
  sourceReferences: DatabaseSourceReference[];
  gaps: (
    | 'source-without-declaration'
    | 'declaration-without-create-migration'
    | 'migration-without-declaration'
  )[];
}
export interface DatabaseContractAnalysis {
  schemaVersion: 1;
  version: string;
  status: ProjectProfileStatus;
  schemaFiles: { file: string; kind: 'prisma' | 'drizzle' | 'sql'; entities: number }[];
  migrationFiles: { file: string; references: number }[];
  entities: DatabaseContractEntity[];
  summary: {
    schemaFiles: number;
    migrationFiles: number;
    declaredEntities: number;
    migrationEntities: number;
    sourceEntities: number;
    linkedEntities: number;
    gapCandidates: number;
  };
  parseFailures: number;
  truncated: boolean;
  limitations: string[];
}
export type WebhookEventDirection = 'produced' | 'consumed';
export interface WebhookEventReference {
  id: string;
  file: string;
  line: number;
  event: string;
  normalizedEvent: string;
  direction: WebhookEventDirection;
  origin: 'branch' | 'return-contract' | 'dispatch-call';
  symbolId?: string;
  componentId?: string;
}
export interface WebhookEndpointContract {
  id: string;
  entrypointId: string;
  file: string;
  line: number;
  route?: string;
  methods: string[];
  componentId?: string;
  reachableSymbolIds: string[];
  callEdgeIds: string[];
  verificationEvidenceIds: string[];
  idempotencyEvidenceIds: string[];
  eventReferenceIds: string[];
  verification: 'evidenced' | 'unverified';
  idempotency: 'evidenced' | 'unverified';
  traversalTruncated: boolean;
}
export interface WebhookEventContract {
  id: string;
  event: string;
  normalizedEvent: string;
  producerReferenceIds: string[];
  consumerReferenceIds: string[];
  status: 'matched-local' | 'external-consumer-boundary' | 'external-producer-boundary';
}
export interface WebhookContractAnalysis {
  schemaVersion: 1;
  version: string;
  status: ProjectProfileStatus;
  endpoints: WebhookEndpointContract[];
  eventReferences: WebhookEventReference[];
  events: WebhookEventContract[];
  summary: {
    endpoints: number;
    verifiedEndpoints: number;
    idempotentEndpoints: number;
    producedEvents: number;
    consumedEvents: number;
    matchedEvents: number;
    externalConsumerBoundaries: number;
    externalProducerBoundaries: number;
  };
  parseFailures: number;
  truncated: boolean;
  limitations: string[];
}
export type FeatureFlagValueKind = 'boolean' | 'string' | 'number' | 'null';
export interface FeatureFlagLiteral {
  kind: FeatureFlagValueKind;
  fingerprint: string;
  display?: string;
}
export interface FeatureFlagDeclaration {
  id: string;
  key: string;
  normalizedKey: string;
  file: string;
  line: number;
  source: 'json-feature-flags' | 'typescript-definition';
  default?: FeatureFlagLiteral;
}
export interface FeatureFlagUsage {
  id: string;
  file: string;
  line: number;
  callee: string;
  context: 'guard' | 'read';
  key?: string;
  normalizedKey?: string;
  componentId?: string;
  default?: FeatureFlagLiteral;
  declarationIds: string[];
  status: 'matched' | 'usage-only' | 'dynamic';
}
export interface FeatureFlagContract {
  id: string;
  key: string;
  normalizedKey: string;
  declarationIds: string[];
  usageIds: string[];
  status: 'matched' | 'declaration-only' | 'usage-only' | 'default-conflict';
}
export interface FeatureFlagAnalysis {
  schemaVersion: 1;
  version: string;
  status: ProjectProfileStatus;
  providers: string[];
  declarations: FeatureFlagDeclaration[];
  usages: FeatureFlagUsage[];
  flags: FeatureFlagContract[];
  summary: {
    providers: number;
    declarationFiles: number;
    declaredFlags: number;
    staticUsages: number;
    dynamicUsages: number;
    matchedFlags: number;
    declarationOnly: number;
    usageOnly: number;
    defaultConflicts: number;
  };
  parseFailures: number;
  truncated: boolean;
  limitations: string[];
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
  packId: 'codebasescan-web-application';
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
  schemaVersion: 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16;
  auditId: string;
  projectName: string;
  createdAt: string;
  snapshotDigest: string;
  filesAnalyzed: number;
  skipped: Record<string, number>;
  truncated: boolean;
  aiMode: 'disabled' | 'ollama' | 'openai';
  auditModes?: AuditModeSelection[];
  findings: Finding[];
  scanners: ScannerRun[];
  dependencies: Dependency[];
  scopePreflight?: AuditScopePreflight;
  projectProfile?: ProjectProfile;
  riskCorrelation?: RiskCorrelation;
  environmentContract?: EnvironmentContractAnalysis;
  testEvidence?: TestEvidenceAnalysis;
  apiContract?: ApiContractAnalysis;
  databaseContract?: DatabaseContractAnalysis;
  webhookContract?: WebhookContractAnalysis;
  featureFlags?: FeatureFlagAnalysis;
  mechanicalAnalysis?: MechanicalAnalysis;
  supplyChainAnalysis?: SupplyChainAnalysis;
  codeQualityAnalysis?: CodeQualityAnalysis;
  checklist?: SecurityChecklist;
  httpProbe?: HttpProbeReport;
  coverage?: CoverageCapability[];
  aiUsage?: AiUsage;
  reviewImport?: {
    schemaVersion: 1;
    ledgerDigest: string;
    sourceAuditIds: string[];
    importedAt: string;
    entries: number;
    applied: number;
    stale: number;
    unmatched: number;
  };
  suppressionImport?: {
    schemaVersion: 1;
    ledgerDigest: string;
    sourceAuditIds: string[];
    importedAt: string;
    entries: number;
    applied: number;
    stale: number;
    unmatched: number;
    expired: number;
  };
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
  componentIds?: string[];
}
export interface ComponentLifecycleSummary {
  componentId: string | null;
  name: string;
  newFindings: number;
  resolvedFindings: number;
  unchangedFindings: number;
  reappearedFindings: number;
  severityChanges: number;
  dispositionChanges: number;
}
export interface AuditComparison {
  schemaVersion: 3;
  baseAuditId: string;
  currentAuditId: string;
  historyReports: number;
  newFindings: FindingReference[];
  resolvedFindings: FindingReference[];
  unchangedFindings: FindingReference[];
  reappearedFindings: FindingReference[];
  severityChanges: {
    finding: FindingReference;
    before: Severity;
    after: Severity;
  }[];
  dispositionChanges: {
    finding: FindingReference;
    before: Disposition;
    after: Disposition;
  }[];
  componentChanges: {
    finding: FindingReference;
    before: string[];
    after: string[];
  }[];
  components: ComponentLifecycleSummary[];
  limitations: string[];
}
