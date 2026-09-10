import { Annotation, END, START, StateGraph, interrupt } from '@langchain/langgraph';
import type { BaseCheckpointSaver } from '@langchain/langgraph-checkpoint';
import type {
  ArchitectureAnalysis,
  ApiContractAnalysis,
  AuditMode,
  AuditReport,
  CodeQualityAnalysis,
  DatabaseContractAnalysis,
  Dependency,
  EnvironmentContractAnalysis,
  DuplicationAnalysis,
  Finding,
  FeatureFlagAnalysis,
  HttpProbeOptions,
  HttpProbeReport,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SupplyChainAnalysis,
  TestEvidenceAnalysis,
  WebhookContractAnalysis,
} from '../domain/types.ts';
import { mergeFindings } from '../domain/findings.ts';
import { buildCoverage } from '../domain/coverage.ts';
import { attachProvenance } from '../domain/provenance.ts';
import { buildSecurityChecklist } from '../domain/checklist.ts';
import { auditModeSelections, modeEnabled, resolveAuditModes } from '../domain/audit-modes.ts';
import { enrichFindingQuality } from '../domain/finding-quality.ts';
import { buildRiskCorrelation } from '../domain/risk-paths.ts';
import { scanPatterns } from '../scanners/builtin.ts';
import { scanPosture } from '../scanners/posture.ts';
import { scanExternal } from '../scanners/external.ts';
import { probeHttp, reconcileHttpPosture, skippedHttpProbe } from '../scanners/http-probe.ts';
import { scanOsv } from '../scanners/osv.ts';
import { profileProject } from '../scanners/project-profile.ts';
import { preferStructuralFindings, scanAstSecurity } from '../scanners/ast-security.ts';
import { scanReactSecurity } from '../scanners/react-security.ts';
import { scanNextSecurity } from '../scanners/next-security.ts';
import { scanSaasSecurity } from '../scanners/saas-security.ts';
import { scanArchitecture, scanDuplication } from '../scanners/mechanical.ts';
import { scanSupplyChain } from '../scanners/supply-chain.ts';
import { scanCodeQuality } from '../scanners/quality.ts';
import { scanAccessibilityStatic } from '../scanners/accessibility-static.ts';
import { scanPrivacyStatic } from '../scanners/privacy-static.ts';
import { scanReliabilityStatic } from '../scanners/reliability-static.ts';
import { scanEnvironmentContract } from '../scanners/environment-contract.ts';
import { scanTestEvidence } from '../scanners/test-evidence.ts';
import { scanApiContract } from '../scanners/api-contract.ts';
import { scanDatabaseContract } from '../scanners/database-contract.ts';
import { scanWebhookContract } from '../scanners/webhook-contract.ts';
import { scanFeatureFlags } from '../scanners/feature-flags.ts';
import { captureSnapshot, redactedSnapshot } from '../security/paths.ts';
import type { Configuration } from '../server/config.ts';
import type { AuditStore } from '../server/store.ts';
import type { Reviewer } from './model.ts';
import { buildReviewGraph } from './review-graph.ts';
const mergeRuns = (left: ScannerRun[], right: ScannerRun[]) => [
  ...new Map([...left, ...right].map((run) => [run.id, run])).values(),
];
function skippedByMode(id: string, name: string, mode: AuditMode): ScannerRun {
  return {
    id,
    name,
    status: 'skipped',
    durationMs: 0,
    findings: 0,
    detail: `Disabled by audit mode selection. Enable ${mode} to run this capability.`,
  };
}
export const AuditState = Annotation.Root({
  auditId: Annotation<string>(),
  executionFingerprint: Annotation<string>({ reducer: (_, value) => value, default: () => '' }),
  snapshotDigest: Annotation<string>({ reducer: (_, value) => value, default: () => '' }),
  fileCount: Annotation<number>({ reducer: (_, value) => value, default: () => 0 }),
  skipped: Annotation<Record<string, number>>({
    reducer: (_, value) => value,
    default: () => ({}),
  }),
  truncated: Annotation<boolean>({ reducer: (_, value) => value, default: () => false }),
  findings: Annotation<Finding[]>({ reducer: mergeFindings, default: () => [] }),
  normalizedFindings: Annotation<Finding[]>({ reducer: (_, value) => value, default: () => [] }),
  scanners: Annotation<ScannerRun[]>({ reducer: mergeRuns, default: () => [] }),
  httpProbe: Annotation<HttpProbeReport | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  dependencies: Annotation<Dependency[]>({ reducer: (_, value) => value, default: () => [] }),
  projectProfile: Annotation<ProjectProfile | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  architectureAnalysis: Annotation<ArchitectureAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  duplicationAnalysis: Annotation<DuplicationAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  supplyChainAnalysis: Annotation<SupplyChainAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  codeQualityAnalysis: Annotation<CodeQualityAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  environmentContract: Annotation<EnvironmentContractAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  testEvidence: Annotation<TestEvidenceAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  apiContract: Annotation<ApiContractAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  databaseContract: Annotation<DatabaseContractAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  webhookContract: Annotation<WebhookContractAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  featureFlags: Annotation<FeatureFlagAnalysis | null>({
    reducer: (_, value) => value,
    default: () => null,
  }),
  analyzed: Annotation<Finding[]>({ reducer: mergeFindings, default: () => [] }),
  cursor: Annotation<number>({ reducer: (_, value) => value, default: () => 0 }),
  reviewNote: Annotation<string>({ reducer: (_, value) => value, default: () => '' }),
  report: Annotation<AuditReport | null>({ reducer: (_, value) => value, default: () => null }),
});
type State = typeof AuditState.State;
const maximumAnalyzedFindings = 12;

function nextReviewableFinding(state: State): { finding: Finding; index: number } | null {
  for (let index = state.cursor; index < state.normalizedFindings.length; index++) {
    const finding = state.normalizedFindings[index];
    if (finding && finding.category !== 'secrets') return { finding, index };
  }
  return null;
}

export function buildAuditGraph(options: {
  root: string;
  projectName: string;
  config: Configuration;
  store: AuditStore;
  checkpointer: BaseCheckpointSaver;
  reviewer: Reviewer | null;
  httpProbe?: HttpProbeOptions;
  gitHistorySecrets?: boolean;
  modes?: AuditMode[];
  humanReview?: boolean;
  signal?: AbortSignal;
}) {
  const {
    root,
    projectName,
    config,
    store,
    checkpointer,
    reviewer,
    httpProbe,
    gitHistorySecrets = false,
    modes,
    humanReview = true,
    signal,
  } = options;
  const enabledModes = new Set(resolveAuditModes(modes));
  let captured: Promise<Snapshot> | null = null;
  const snapshot = () => (captured ??= captureSnapshot(root));
  const event = (state: State, stage: string, message: string) =>
    store.event(state.auditId, stage, stage, message);
  const checkedSnapshot = async (state: State) => {
    signal?.throwIfAborted();
    const source = await snapshot();
    if (state.snapshotDigest && state.snapshotDigest !== source.digest)
      throw new Error(
        'Source changed after the checkpoint. Start a new audit; evidence from different snapshots will not be mixed.',
      );
    return source;
  };
  return new StateGraph(AuditState)
    .addNode('snapshot', async (state) => {
      const source = await snapshot();
      event(
        state,
        'snapshot',
        `Captured ${source.files.length} files without running the target project.`,
      );
      return {
        snapshotDigest: source.digest,
        fileCount: source.files.length,
        skipped: source.skipped,
        truncated: source.truncated,
      };
    })
    .addNode('patterns', async (state) => {
      if (!modeEnabled(enabledModes, 'security'))
        return {
          findings: [],
          scanners: [skippedByMode('builtin', 'Built-in patterns', 'security')],
        };
      const started = performance.now();
      const source = await checkedSnapshot(state);
      const findings = scanPatterns(source);
      event(
        state,
        'patterns',
        `${findings.length} deterministic review candidates. None are automatically confirmed.`,
      );
      return {
        findings,
        scanners: [
          {
            id: 'builtin',
            name: 'Built-in patterns',
            status: findings.length >= 300 || source.truncated ? 'partial' : 'completed',
            durationMs: Math.max(0, Math.round(performance.now() - started)),
            findings: findings.length,
            detail:
              'Seven bounded regex heuristics. Not a complete SAST engine or interprocedural analysis.',
            version: '0.2.0',
          } satisfies ScannerRun,
        ],
      };
    })
    .addNode('project_profile', async (state) => {
      const result = profileProject(await checkedSnapshot(state));
      event(state, 'project_profile', `Project structure profile: ${result.profile.status}.`);
      return { projectProfile: result.profile, scanners: [result.run] };
    })
    .addNode('ast_security', async (state) => {
      if (!modeEnabled(enabledModes, 'security'))
        return {
          findings: [],
          scanners: [skippedByMode('ast-security', 'Framework-aware authorization', 'security')],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to AST analysis.');
      const result = scanAstSecurity(await checkedSnapshot(state), state.projectProfile);
      event(
        state,
        'ast_security',
        `${result.findings.length} framework-aware structural candidate(s).`,
      );
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('saas_security', async (state) => {
      if (!modeEnabled(enabledModes, 'saas'))
        return {
          findings: [],
          scanners: [skippedByMode('saas-security', 'SaaS application security', 'saas')],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to SaaS security analysis.');
      const result = scanSaasSecurity(await checkedSnapshot(state), state.projectProfile);
      event(state, 'saas_security', `${result.findings.length} SaaS security candidate(s).`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('react_security', async (state) => {
      if (!modeEnabled(enabledModes, 'security', 'next-react'))
        return {
          findings: [],
          scanners: [skippedByMode('react-security', 'React client security', 'next-react')],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to React security analysis.');
      const result = scanReactSecurity(await checkedSnapshot(state), state.projectProfile);
      event(state, 'react_security', `${result.findings.length} React security candidate(s).`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('next_security', async (state) => {
      if (!modeEnabled(enabledModes, 'security', 'next-react'))
        return {
          findings: [],
          scanners: [skippedByMode('next-security', 'Next.js application security', 'next-react')],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to Next.js security analysis.');
      const result = scanNextSecurity(await checkedSnapshot(state), state.projectProfile);
      event(state, 'next_security', `${result.findings.length} Next.js security candidate(s).`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('accessibility_static', async (state) => {
      if (!modeEnabled(enabledModes, 'accessibility-static'))
        return {
          findings: [],
          scanners: [
            skippedByMode(
              'accessibility-static',
              'Static accessibility review',
              'accessibility-static',
            ),
          ],
        };
      const result = scanAccessibilityStatic(await checkedSnapshot(state));
      event(
        state,
        'accessibility_static',
        `${result.findings.length} static accessibility candidate(s).`,
      );
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('privacy_static', async (state) => {
      if (!modeEnabled(enabledModes, 'privacy'))
        return {
          findings: [],
          scanners: [skippedByMode('privacy-static', 'Static privacy review', 'privacy')],
        };
      const result = scanPrivacyStatic(await checkedSnapshot(state));
      event(state, 'privacy_static', `${result.findings.length} static privacy candidate(s).`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('reliability_static', async (state) => {
      if (!modeEnabled(enabledModes, 'reliability'))
        return {
          findings: [],
          scanners: [
            skippedByMode('reliability-static', 'Static reliability review', 'reliability'),
          ],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to reliability analysis.');
      const result = scanReliabilityStatic(await checkedSnapshot(state), state.projectProfile);
      event(
        state,
        'reliability_static',
        `${result.findings.length} static reliability candidate(s).`,
      );
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('environment_contract', async (state) => {
      if (!modeEnabled(enabledModes, 'release-readiness'))
        return {
          findings: [],
          environmentContract: null,
          scanners: [
            skippedByMode(
              'environment-contract',
              'Environment contract consistency',
              'release-readiness',
            ),
          ],
        };
      const result = scanEnvironmentContract(await checkedSnapshot(state));
      event(
        state,
        'environment_contract',
        `${result.analysis.summary.undocumented} undocumented environment name(s); values were not retained.`,
      );
      return {
        findings: result.findings,
        environmentContract: result.analysis,
        scanners: [result.run],
      };
    })
    .addNode('test_evidence', async (state) => {
      if (!modeEnabled(enabledModes, 'release-readiness'))
        return {
          testEvidence: null,
          scanners: [
            skippedByMode('test-evidence', 'Security-critical test evidence', 'release-readiness'),
          ],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to test evidence analysis.');
      const result = scanTestEvidence(await checkedSnapshot(state), state.projectProfile);
      event(
        state,
        'test_evidence',
        `${result.analysis.withRelatedTests} of ${result.analysis.criticalFiles} critical source file(s) have related captured test imports.`,
      );
      return { testEvidence: result.analysis, scanners: [result.run] };
    })
    .addNode('api_contract', async (state) => {
      if (!modeEnabled(enabledModes, 'release-readiness'))
        return {
          apiContract: null,
          scanners: [
            skippedByMode('api-contract', 'API contract consistency', 'release-readiness'),
          ],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to API contract analysis.');
      const result = scanApiContract(await checkedSnapshot(state), state.projectProfile);
      event(
        state,
        'api_contract',
        result.analysis.status === 'unsupported'
          ? 'No captured OpenAPI or Swagger specification was available.'
          : `${result.analysis.summary.matchedOperations} declared operation(s) matched source; ${result.analysis.summary.declaredOnly} declared-only and ${result.analysis.summary.sourceOnly} source-only candidate(s).`,
      );
      return { apiContract: result.analysis, scanners: [result.run] };
    })
    .addNode('database_contract', async (state) => {
      if (!modeEnabled(enabledModes, 'release-readiness'))
        return {
          databaseContract: null,
          scanners: [
            skippedByMode(
              'database-contract',
              'Database schema and migration consistency',
              'release-readiness',
            ),
          ],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to database contract analysis.');
      const result = scanDatabaseContract(await checkedSnapshot(state), state.projectProfile);
      event(
        state,
        'database_contract',
        result.analysis.status === 'unsupported'
          ? 'No captured database schema or migration declaration was available.'
          : `${result.analysis.summary.linkedEntities} linked database entity record(s); ${result.analysis.summary.gapCandidates} consistency candidate(s).`,
      );
      return { databaseContract: result.analysis, scanners: [result.run] };
    })
    .addNode('webhook_contract', async (state) => {
      if (!modeEnabled(enabledModes, 'release-readiness'))
        return {
          webhookContract: null,
          scanners: [
            skippedByMode(
              'webhook-contract',
              'Webhook endpoint and event contract',
              'release-readiness',
            ),
          ],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to webhook contract analysis.');
      const result = scanWebhookContract(await checkedSnapshot(state), state.projectProfile);
      event(
        state,
        'webhook_contract',
        result.analysis.status === 'unsupported'
          ? 'No statically mapped webhook endpoint was available.'
          : `${result.analysis.summary.endpoints} webhook endpoint(s); ${result.analysis.summary.verifiedEndpoints} with verification evidence and ${result.analysis.summary.matchedEvents} locally paired event name(s).`,
      );
      return { webhookContract: result.analysis, scanners: [result.run] };
    })
    .addNode('feature_flags', async (state) => {
      if (!modeEnabled(enabledModes, 'release-readiness'))
        return {
          featureFlags: null,
          scanners: [
            skippedByMode(
              'feature-flags',
              'Feature flag declaration and usage consistency',
              'release-readiness',
            ),
          ],
        };
      if (!state.projectProfile)
        throw new Error('Project profile was not available to feature flag analysis.');
      const result = scanFeatureFlags(await checkedSnapshot(state), state.projectProfile);
      event(
        state,
        'feature_flags',
        result.analysis.status === 'unsupported'
          ? 'No supported feature flag declaration, provider, or evaluation call was available.'
          : `${result.analysis.summary.declaredFlags} declared flag(s), ${result.analysis.summary.matchedFlags} matched, ${result.analysis.summary.usageOnly} usage-only, and ${result.analysis.summary.defaultConflicts} default conflict candidate(s).`,
      );
      return { featureFlags: result.analysis, scanners: [result.run] };
    })
    .addNode('architecture', async (state) => {
      if (!modeEnabled(enabledModes, 'maintainability'))
        return {
          architectureAnalysis: null,
          scanners: [
            skippedByMode(
              'dependency-cruiser',
              'JavaScript/TypeScript dependency structure',
              'maintainability',
            ),
          ],
        };
      const result = await scanArchitecture(
        await checkedSnapshot(state),
        state.projectProfile ?? undefined,
        config.temporaryDirectory,
        signal,
      );
      event(state, 'architecture', `Dependency structure: ${result.run.status}.`);
      return {
        architectureAnalysis: result.analysis ?? null,
        scanners: [result.run],
      };
    })
    .addNode('duplication', async (state) => {
      if (!modeEnabled(enabledModes, 'maintainability'))
        return {
          duplicationAnalysis: null,
          scanners: [
            skippedByMode('jscpd', 'JavaScript/TypeScript code duplication', 'maintainability'),
          ],
        };
      const result = await scanDuplication(
        await checkedSnapshot(state),
        config.temporaryDirectory,
        signal,
      );
      event(state, 'duplication', `Code duplication: ${result.run.status}.`);
      return {
        duplicationAnalysis: result.analysis ?? null,
        scanners: [result.run],
      };
    })
    .addNode('supply_chain', async (state) => {
      if (!modeEnabled(enabledModes, 'security', 'release-readiness'))
        return {
          findings: [],
          supplyChainAnalysis: null,
          scanners: [
            skippedByMode('supply-chain', 'Node.js supply-chain integrity', 'release-readiness'),
          ],
        };
      const result = scanSupplyChain(await checkedSnapshot(state));
      event(state, 'supply_chain', `Node.js supply-chain integrity: ${result.run.status}.`);
      return {
        findings: result.findings,
        supplyChainAnalysis: result.analysis,
        scanners: [result.run],
      };
    })
    .addNode('code_quality', async (state) => {
      if (!modeEnabled(enabledModes, 'maintainability'))
        return {
          codeQualityAnalysis: null,
          scanners: [
            skippedByMode('quality-metrics', 'Code quality metrics', 'maintainability'),
            skippedByMode('knip', 'Dead code and dependency usage', 'maintainability'),
          ],
        };
      const result = await scanCodeQuality(
        await checkedSnapshot(state),
        state.projectProfile ?? undefined,
        config.temporaryDirectory,
        signal,
      );
      event(state, 'code_quality', 'Static quality and dead-code analysis completed.');
      return { codeQualityAnalysis: result.analysis, scanners: result.runs };
    })
    .addNode('posture', async (state) => {
      if (!modeEnabled(enabledModes, 'security', 'release-readiness'))
        return {
          findings: [],
          scanners: [skippedByMode('posture', 'Application security posture', 'release-readiness')],
        };
      const started = performance.now();
      const source = await checkedSnapshot(state);
      const findings = scanPosture(source, { includeStructuralCandidates: false });
      event(
        state,
        'posture',
        `${findings.length} application security posture candidates. Declared configuration is kept distinct from runtime behavior.`,
      );
      return {
        findings,
        scanners: [
          {
            id: 'posture',
            name: 'Application security posture',
            status: findings.length >= 300 || source.truncated ? 'partial' : 'completed',
            durationMs: Math.max(0, Math.round(performance.now() - started)),
            findings: findings.length,
            detail:
              'Conservative checks for security headers, session cookies, CORS, route and server-action authorization, and environment configuration in TypeScript/Node.js/Next.js projects.',
            version: '0.2.0',
          } satisfies ScannerRun,
        ],
      };
    })
    .addNode('semgrep', async (state) => {
      if (!modeEnabled(enabledModes, 'security'))
        return {
          findings: [],
          scanners: [skippedByMode('semgrep', 'Semgrep', 'security')],
        };
      const result = await scanExternal(
        'semgrep',
        await checkedSnapshot(state),
        config.semgrep,
        config.temporaryDirectory,
        config.rulesDirectory,
        signal,
      );
      event(state, 'semgrep', `Semgrep: ${result.run.status}.`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('gitleaks', async (state) => {
      if (!modeEnabled(enabledModes, 'security'))
        return {
          findings: [],
          scanners: [skippedByMode('gitleaks', 'Gitleaks', 'security')],
        };
      const result = await scanExternal(
        'gitleaks',
        await checkedSnapshot(state),
        config.gitleaks,
        config.temporaryDirectory,
        config.rulesDirectory,
        signal,
        { projectRoot: root, gitHistory: gitHistorySecrets },
      );
      event(state, 'gitleaks', `Gitleaks: ${result.run.status}.`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('http_probe', async (state) => {
      if (!modeEnabled(enabledModes, 'security'))
        return {
          findings: [],
          scanners: [skippedByMode('http-probe', 'HTTP runtime posture', 'security')],
          httpProbe: null,
        };
      const result = httpProbe ? await probeHttp(httpProbe, signal) : skippedHttpProbe();
      event(state, 'http_probe', `HTTP runtime posture: ${result.run.status}.`);
      return {
        findings: result.findings,
        scanners: [result.run],
        httpProbe: result.report ?? null,
      };
    })
    .addNode('inventory', async (state) => {
      if (!modeEnabled(enabledModes, 'security'))
        return {
          dependencies: [],
          findings: [],
          scanners: [skippedByMode('osv', 'Dependency vulnerabilities', 'security')],
        };
      const result = await scanOsv(
        await checkedSnapshot(state),
        config.osv,
        config.advisoryDatabasePath,
        config.osvCacheHours,
        signal,
      );
      event(
        state,
        'inventory',
        `Collected ${result.dependencies.length} dependencies. OSV: ${result.run.status}.`,
      );
      return {
        dependencies: result.dependencies,
        findings: result.findings,
        scanners: [result.run],
      };
    })
    .addNode('normalize', (state) => {
      const normalizedFindings = enrichFindingQuality(
        preferStructuralFindings(
          reconcileHttpPosture(state.findings, state.httpProbe ?? undefined),
        ),
        state.projectProfile ?? undefined,
        state.httpProbe ?? undefined,
      );
      event(
        state,
        'normalize',
        `Normalized ${normalizedFindings.length} candidates. Related static and observed HTTP posture evidence was reconciled without discarding either evidence source.`,
      );
      return { normalizedFindings };
    })
    .addNode('investigate', async (state) => {
      if (!reviewer) return { cursor: state.normalizedFindings.length };
      const reviewable = nextReviewableFinding(state);
      if (!reviewable) return { cursor: state.normalizedFindings.length };
      const { finding, index } = reviewable;
      const source = redactedSnapshot(await checkedSnapshot(state));
      const graph = buildReviewGraph(source, reviewer, state.projectProfile ?? undefined, signal);
      const result = await graph.invoke({ finding }, { signal, recursionLimit: 12 });
      const reviewed = { ...finding, ...(result.analysis ? { analysis: result.analysis } : {}) };
      store.event(
        state.auditId,
        `investigate:${finding.id}`,
        'investigate',
        `Reviewed ${finding.ruleId}; source disposition remains ${finding.disposition}.`,
      );
      return { analyzed: [reviewed], cursor: index + 1 };
    })
    .addNode('prepare_report', (state) => {
      const createdAt = new Date().toISOString();
      const audit = store.audit(state.auditId);
      const scopePreflight = audit.options.scopePreflight;
      const findings = store.applySuppressions(
        audit.projectId,
        attachProvenance(
          mergeFindings(state.normalizedFindings, state.analyzed),
          state.scanners,
          createdAt,
        ),
      );
      const modelAnalyses = findings.flatMap((finding) =>
        finding.analysis?.provider ? [finding.analysis] : [],
      );
      const storedUsage = store.aiUsage(state.auditId);
      const checklist = buildSecurityChecklist({
        ...(state.projectProfile ? { projectProfile: state.projectProfile } : {}),
        findings,
        scanners: state.scanners,
        ...(state.httpProbe ? { httpProbe: state.httpProbe } : {}),
        dependencies: state.dependencies,
      });
      const riskCorrelation = state.projectProfile
        ? buildRiskCorrelation(state.projectProfile, findings)
        : undefined;
      const mechanicalAnalysis =
        state.architectureAnalysis || state.duplicationAnalysis
          ? {
              schemaVersion: 1 as const,
              ...(state.architectureAnalysis ? { architecture: state.architectureAnalysis } : {}),
              ...(state.duplicationAnalysis ? { duplication: state.duplicationAnalysis } : {}),
            }
          : undefined;
      const report: AuditReport = {
        schemaVersion: 13,
        auditId: state.auditId,
        projectName,
        createdAt,
        snapshotDigest: state.snapshotDigest,
        filesAnalyzed: state.fileCount,
        skipped: state.skipped,
        truncated: state.truncated,
        aiMode: config.aiMode,
        auditModes: auditModeSelections(modes),
        findings,
        scanners: state.scanners,
        dependencies: state.dependencies,
        ...(scopePreflight ? { scopePreflight } : {}),
        ...(state.projectProfile ? { projectProfile: state.projectProfile } : {}),
        ...(riskCorrelation ? { riskCorrelation } : {}),
        ...(state.environmentContract ? { environmentContract: state.environmentContract } : {}),
        ...(state.testEvidence ? { testEvidence: state.testEvidence } : {}),
        ...(state.apiContract ? { apiContract: state.apiContract } : {}),
        ...(state.databaseContract ? { databaseContract: state.databaseContract } : {}),
        ...(state.webhookContract ? { webhookContract: state.webhookContract } : {}),
        ...(state.featureFlags ? { featureFlags: state.featureFlags } : {}),
        ...(mechanicalAnalysis ? { mechanicalAnalysis } : {}),
        ...(state.supplyChainAnalysis ? { supplyChainAnalysis: state.supplyChainAnalysis } : {}),
        ...(state.codeQualityAnalysis ? { codeQualityAnalysis: state.codeQualityAnalysis } : {}),
        checklist,
        ...(state.httpProbe ? { httpProbe: state.httpProbe } : {}),
        coverage: buildCoverage(state.scanners, findings, config.aiMode),
        ...(config.aiMode !== 'disabled'
          ? {
              aiUsage: {
                provider: config.aiMode,
                models: [...new Set(modelAnalyses.flatMap((analysis) => analysis.model ?? []))],
                calls: config.aiMode === 'openai' ? storedUsage.calls : modelAnalyses.length,
                cacheHits: config.aiMode === 'openai' ? storedUsage.cacheHits : 0,
                inputTokens:
                  config.aiMode === 'openai'
                    ? storedUsage.inputTokens
                    : modelAnalyses.reduce(
                        (sum, analysis) => sum + (analysis.tokenUsage?.inputTokens ?? 0),
                        0,
                      ),
                outputTokens:
                  config.aiMode === 'openai'
                    ? storedUsage.outputTokens
                    : modelAnalyses.reduce(
                        (sum, analysis) => sum + (analysis.tokenUsage?.outputTokens ?? 0),
                        0,
                      ),
                ...(config.aiMode === 'openai' &&
                (config.openaiInputCostPerMillion !== undefined ||
                  config.openaiOutputCostPerMillion !== undefined)
                  ? { approximateCostUsd: storedUsage.approximateCostUsd }
                  : {}),
                contextFilesSent: [
                  ...new Set(modelAnalyses.flatMap((analysis) => analysis.contextFilesSent ?? [])),
                ],
                contextIdsSent: [
                  ...new Set(modelAnalyses.flatMap((analysis) => analysis.contextIdsSent ?? [])),
                ],
                redactionApplied: modelAnalyses.some(
                  (analysis) => analysis.redactionApplied === true,
                ),
              },
            }
          : {}),
        publication: 'draft',
        limitations: [
          'This is a bounded static review, not a pentest, compliance audit, or security certification.',
          'No target code, package lifecycle script, exploit, crawl, or arbitrary request is executed.',
          ...(state.httpProbe
            ? [
                'HTTP observations apply only to the explicitly approved URL, response, and time; they do not establish whole-application runtime coverage.',
              ]
            : ['HTTP runtime posture was not run because no target was explicitly approved.']),
          'AI assessments cannot confirm findings, lower scanner severity, or suppress candidates automatically.',
          'Dependency resolution is limited to captured npm, pnpm, and Yarn lockfiles. OSV presence does not establish runtime reachability or exploitability.',
          'Supply-chain checks inspect captured declarations and integrity metadata; private registries and intentional local dependencies still require trust review.',
          'Dependency cycles, orphan modules, coupling, and duplicated blocks are maintainability evidence. They are not security vulnerabilities by themselves.',
          'Dead-code and complexity results are bounded maintenance candidates. Dynamic imports, generated routes, framework conventions, and runtime registration can make apparently unused code reachable.',
          'Imported coverage artifacts describe a prior test run and do not prove which commit, environment, or security behavior was exercised.',
          'Secret files, Git history, symlinks, binary files, generated output and unsupported formats are excluded.',
          'Regex patterns can match comments and miss indirect flows; middleware, RLS and runtime policy need human review.',
          ...(reviewer &&
          state.normalizedFindings.filter((finding) => finding.category !== 'secrets').length >
            maximumAnalyzedFindings
            ? [
                `Contextual analysis was limited to ${maximumAnalyzedFindings} candidates. Remaining candidates are preserved without contextual assessment.`,
              ]
            : []),
          ...(state.truncated
            ? [
                'The source snapshot was truncated. Review skipped files before relying on coverage.',
              ]
            : []),
          ...(scopePreflight?.predictedTruncated
            ? [
                'The pre-audit scope estimate predicted truncation and the operator explicitly approved a partial snapshot.',
              ]
            : []),
        ],
      };
      store.saveProgress(state.auditId, report);
      event(
        state,
        'prepare_report',
        humanReview
          ? 'Draft report saved. Waiting for an analyst to review publication.'
          : 'Draft report saved for non-interactive execution. Findings remain unconfirmed.',
      );
      return { report };
    })
    .addNode('human_review', () => {
      const decision = interrupt({
        kind: 'publication_review',
        message:
          'Review the evidence before publishing. Publishing does not confirm unresolved findings.',
      }) as {
        note?: unknown;
      };
      if (typeof decision?.note !== 'string' || decision.note.trim().length < 12)
        throw new Error('A publication review note is required.');
      return { reviewNote: decision.note.trim().slice(0, 2000) };
    })
    .addNode('publish', (state) => {
      if (!state.report) throw new Error('No report was prepared.');
      const latest = store.audit(state.auditId).report;
      const report: AuditReport = {
        ...state.report,
        findings: latest?.findings ?? state.report.findings,
        checklist: latest?.checklist ?? state.report.checklist,
        publication: 'reviewed',
        reviewNote: state.reviewNote,
      };
      store.saveProgress(state.auditId, report);
      event(state, 'publish', 'Report published with review dispositions and limitations intact.');
      return { report };
    })
    .addEdge(START, 'snapshot')
    .addEdge('snapshot', 'patterns')
    .addEdge('snapshot', 'project_profile')
    .addEdge('project_profile', 'ast_security')
    .addEdge('project_profile', 'saas_security')
    .addEdge('project_profile', 'next_security')
    .addEdge('project_profile', 'react_security')
    .addEdge('project_profile', 'accessibility_static')
    .addEdge('project_profile', 'privacy_static')
    .addEdge('project_profile', 'reliability_static')
    .addEdge('snapshot', 'environment_contract')
    .addEdge('project_profile', 'test_evidence')
    .addEdge('project_profile', 'api_contract')
    .addEdge('project_profile', 'database_contract')
    .addEdge('project_profile', 'webhook_contract')
    .addEdge('project_profile', 'feature_flags')
    .addEdge('project_profile', 'architecture')
    .addEdge('project_profile', 'code_quality')
    .addEdge('snapshot', 'duplication')
    .addEdge('snapshot', 'supply_chain')
    .addEdge('snapshot', 'posture')
    .addEdge('snapshot', 'semgrep')
    .addEdge('snapshot', 'gitleaks')
    .addEdge('snapshot', 'http_probe')
    .addEdge('snapshot', 'inventory')
    .addEdge(
      [
        'patterns',
        'ast_security',
        'saas_security',
        'next_security',
        'react_security',
        'accessibility_static',
        'privacy_static',
        'reliability_static',
        'environment_contract',
        'test_evidence',
        'api_contract',
        'database_contract',
        'webhook_contract',
        'feature_flags',
        'architecture',
        'duplication',
        'supply_chain',
        'code_quality',
        'posture',
        'semgrep',
        'gitleaks',
        'http_probe',
        'inventory',
      ],
      'normalize',
    )
    .addConditionalEdges('normalize', (state) =>
      reviewer && nextReviewableFinding(state) ? 'investigate' : 'prepare_report',
    )
    .addConditionalEdges('investigate', (state) =>
      state.analyzed.length < maximumAnalyzedFindings && nextReviewableFinding(state)
        ? 'investigate'
        : 'prepare_report',
    )
    .addConditionalEdges('prepare_report', () => (humanReview ? 'human_review' : END))
    .addEdge('human_review', 'publish')
    .addEdge('publish', END)
    .compile({ checkpointer });
}
