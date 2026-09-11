import path from 'node:path';
import {
  DeterministicPipeline,
  PIPELINE_END as END,
  PIPELINE_START as START,
} from './deterministic-pipeline.ts';
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
import { auditReportSchemaVersion } from '../domain/versions.ts';
import { scanPatterns } from '../scanners/builtin.ts';
import { scanPosture } from '../scanners/posture.ts';
import { scanExternal } from '../scanners/external.ts';
import { probeHttp, reconcileHttpPosture, skippedHttpProbe } from '../scanners/http-probe.ts';
import { scanOsv } from '../scanners/osv.ts';
import { profileProject, projectProfileScannerVersion } from '../scanners/project-profile.ts';
import { preferStructuralFindings, scanAstSecurity } from '../scanners/ast-security.ts';
import { scanReactSecurity } from '../scanners/react-security.ts';
import { scanNextSecurity } from '../scanners/next-security.ts';
import { scanSaasSecurity } from '../scanners/saas-security.ts';
import { scanArchitecture, scanDuplication } from '../scanners/mechanical.ts';
import { scanSupplyChain } from '../scanners/supply-chain.ts';
import { scanCodeQuality } from '../scanners/quality.ts';
import { scanAccessibilityStatic } from '../scanners/accessibility-static.ts';
import { scanWebPosture } from '../scanners/web-posture.ts';
import { scanPrivacyStatic } from '../scanners/privacy-static.ts';
import { scanReliabilityStatic } from '../scanners/reliability-static.ts';
import { scanEnvironmentContract } from '../scanners/environment-contract.ts';
import { scanTestEvidence } from '../scanners/test-evidence.ts';
import { scanApiContract } from '../scanners/api-contract.ts';
import { scanDatabaseContract } from '../scanners/database-contract.ts';
import { scanWebhookContract } from '../scanners/webhook-contract.ts';
import { scanFeatureFlags } from '../scanners/feature-flags.ts';
import { captureSnapshot } from '../security/paths.ts';
import type { Configuration } from '../server/config.ts';
import type { AuditExecutionStore } from './audit-store.ts';
import { runCachedScan } from './scanner-cache.ts';
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
interface State {
  auditId: string;
  snapshotDigest: string;
  fileCount: number;
  skipped: Record<string, number>;
  truncated: boolean;
  findings: Finding[];
  normalizedFindings: Finding[];
  scanners: ScannerRun[];
  httpProbe: HttpProbeReport | null;
  dependencies: Dependency[];
  projectProfile: ProjectProfile | null;
  architectureAnalysis: ArchitectureAnalysis | null;
  duplicationAnalysis: DuplicationAnalysis | null;
  supplyChainAnalysis: SupplyChainAnalysis | null;
  codeQualityAnalysis: CodeQualityAnalysis | null;
  environmentContract: EnvironmentContractAnalysis | null;
  testEvidence: TestEvidenceAnalysis | null;
  apiContract: ApiContractAnalysis | null;
  databaseContract: DatabaseContractAnalysis | null;
  webhookContract: WebhookContractAnalysis | null;
  featureFlags: FeatureFlagAnalysis | null;
  report: AuditReport | null;
}

function initialState(input: { auditId: string }): State {
  return {
    auditId: input.auditId,
    snapshotDigest: '',
    fileCount: 0,
    skipped: {},
    truncated: false,
    findings: [],
    normalizedFindings: [],
    scanners: [],
    httpProbe: null,
    dependencies: [],
    projectProfile: null,
    architectureAnalysis: null,
    duplicationAnalysis: null,
    supplyChainAnalysis: null,
    codeQualityAnalysis: null,
    environmentContract: null,
    testEvidence: null,
    apiContract: null,
    databaseContract: null,
    webhookContract: null,
    featureFlags: null,
    report: null,
  };
}

function mergeState(state: State, update: Partial<State>): State {
  return {
    ...state,
    ...update,
    findings: update.findings ? mergeFindings(state.findings, update.findings) : state.findings,
    scanners: update.scanners ? mergeRuns(state.scanners, update.scanners) : state.scanners,
  };
}

export function buildAuditPipeline(options: {
  root: string;
  projectName: string;
  config: Configuration;
  store: AuditExecutionStore;
  httpProbe?: HttpProbeOptions;
  gitHistorySecrets?: boolean;
  modes?: AuditMode[];
  signal?: AbortSignal;
}) {
  const {
    root,
    projectName,
    config,
    store,
    httpProbe,
    gitHistorySecrets = false,
    modes,
    signal,
  } = options;
  const enabledModes = new Set(resolveAuditModes(modes));
  const scannerCache = {
    directory: config.scannerCacheDirectory ?? path.join(config.dataDirectory, 'scanner-cache'),
    enabled: config.scannerCache ?? true,
  };
  const projectProfileCacheVariant = `project-profile@${projectProfileScannerVersion}`;
  const cachedScan = <T>(
    source: Snapshot,
    scannerId: string,
    scannerVersion: string,
    expectedRunIds: string[],
    execute: () => Promise<T> | T,
    variant = '',
  ) =>
    runCachedScan(
      scannerCache,
      {
        snapshotDigest: source.digest,
        scannerId,
        scannerVersion,
        expectedRunIds,
        ...(variant ? { variant } : {}),
      },
      execute,
    );
  let captured: Promise<Snapshot> | null = null;
  const snapshot = () => (captured ??= captureSnapshot(root));
  const event = (state: State, stage: string, message: string) =>
    store.event(state.auditId, stage, stage, message);
  const checkedSnapshot = async (state: State) => {
    signal?.throwIfAborted();
    const source = await snapshot();
    if (state.snapshotDigest && state.snapshotDigest !== source.digest)
      throw new Error(
        'Source changed during the audit. Start a new audit; evidence from different snapshots will not be mixed.',
      );
    return source;
  };
  return new DeterministicPipeline<State, { auditId: string }>(initialState, mergeState)
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(source, 'builtin', '0.4.1', ['builtin'], () => {
        const started = performance.now();
        const findings = scanPatterns(source);
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
              version: '0.4.1',
            } satisfies ScannerRun,
          ],
        };
      });
      event(
        state,
        'patterns',
        `${result.findings.length} deterministic review candidates. None are automatically confirmed.`,
      );
      return result;
    })
    .addNode('project_profile', async (state) => {
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'project-profile',
        projectProfileScannerVersion,
        ['project-profile'],
        () => profileProject(source),
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'ast-security',
        '0.5.0',
        ['ast-security'],
        () => scanAstSecurity(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'saas-security',
        '0.4.0',
        ['saas-security'],
        () => scanSaasSecurity(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'react-security',
        '0.4.2',
        ['react-security'],
        () => scanReactSecurity(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'next-security',
        '0.4.2',
        ['next-security'],
        () => scanNextSecurity(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
            skippedByMode(
              'axe-results',
              'Imported Axe runtime accessibility',
              'accessibility-static',
            ),
          ],
        };
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'accessibility-static',
        '0.4.0',
        ['accessibility-static', 'axe-results'],
        () => scanAccessibilityStatic(source),
      );
      event(
        state,
        'accessibility_static',
        `${result.findings.length} static accessibility candidate(s).`,
      );
      return { findings: result.findings, scanners: result.runs };
    })
    .addNode('web_posture', async (state) => {
      if (!modeEnabled(enabledModes, 'web-posture'))
        return {
          findings: [],
          scanners: [skippedByMode('web-posture', 'Web discovery and SEO posture', 'web-posture')],
        };
      const source = await checkedSnapshot(state);
      const result = await cachedScan(source, 'web-posture', '0.5.0', ['web-posture'], () =>
        scanWebPosture(source),
      );
      event(state, 'web_posture', `${result.findings.length} web posture candidate(s).`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('privacy_static', async (state) => {
      if (!modeEnabled(enabledModes, 'privacy'))
        return {
          findings: [],
          scanners: [skippedByMode('privacy-static', 'Static privacy review', 'privacy')],
        };
      const source = await checkedSnapshot(state);
      const result = await cachedScan(source, 'privacy-static', '0.3.0', ['privacy-static'], () =>
        scanPrivacyStatic(source),
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'reliability-static',
        '0.2.0',
        ['reliability-static'],
        () => scanReliabilityStatic(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'environment-contract',
        '1.3.0',
        ['environment-contract'],
        () => scanEnvironmentContract(source),
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'test-evidence',
        '1.0.0',
        ['test-evidence'],
        () => scanTestEvidence(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'api-contract',
        '1.0.0',
        ['api-contract'],
        () => scanApiContract(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'database-contract',
        '1.0.0',
        ['database-contract'],
        () => scanDatabaseContract(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'webhook-contract',
        '1.0.0',
        ['webhook-contract'],
        () => scanWebhookContract(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'feature-flags',
        '1.0.0',
        ['feature-flags'],
        () => scanFeatureFlags(source, state.projectProfile!),
        projectProfileCacheVariant,
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'dependency-cruiser',
        '18.2.0',
        ['dependency-cruiser'],
        () =>
          scanArchitecture(
            source,
            state.projectProfile ?? undefined,
            config.temporaryDirectory,
            signal,
          ),
        projectProfileCacheVariant,
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(source, 'jscpd', '5.2.0', ['jscpd'], () =>
        scanDuplication(source, config.temporaryDirectory, signal),
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(source, 'supply-chain', '0.1.0', ['supply-chain'], () =>
        scanSupplyChain(source),
      );
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(
        source,
        'code-quality',
        'quality@0.2.0+knip@6.35.1+typescript@5.9.3',
        ['quality-metrics', 'knip'],
        () =>
          scanCodeQuality(
            source,
            state.projectProfile ?? undefined,
            config.temporaryDirectory,
            signal,
          ),
        projectProfileCacheVariant,
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
      const source = await checkedSnapshot(state);
      const result = await cachedScan(source, 'posture', '0.2.0', ['posture'], () => {
        const started = performance.now();
        const findings = scanPosture(source, { includeStructuralCandidates: false });
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
      });
      event(
        state,
        'posture',
        `${result.findings.length} application security posture candidates. Declared configuration is kept distinct from runtime behavior.`,
      );
      return result;
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
          state.projectProfile ?? undefined,
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
    .addNode('prepare_report', (state) => {
      const createdAt = new Date().toISOString();
      const audit = store.audit(state.auditId);
      const scopePreflight = audit.options.scopePreflight;
      const findings = store.applySuppressions(
        audit.projectId,
        attachProvenance(state.normalizedFindings, state.scanners, createdAt),
      );
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
        schemaVersion: auditReportSchemaVersion,
        auditId: state.auditId,
        projectName,
        createdAt,
        snapshotDigest: state.snapshotDigest,
        filesAnalyzed: state.fileCount,
        skipped: state.skipped,
        truncated: state.truncated,
        aiMode: 'disabled',
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
        coverage: buildCoverage(state.scanners),
        publication: 'draft',
        limitations: [
          'This is a bounded static review, not a pentest, compliance audit, or security certification.',
          'No target code, package lifecycle script, exploit, crawl, or arbitrary request is executed.',
          ...(state.httpProbe
            ? [
                'HTTP observations apply only to the explicitly approved URL, response, and time; they do not establish whole-application runtime coverage.',
              ]
            : ['HTTP runtime posture was not run because no target was explicitly approved.']),
          'Agent review is external to the audit. Agent conclusions must remain separate from deterministic scanner evidence.',
          'Dependency resolution is limited to captured npm, pnpm, and Yarn lockfiles. OSV presence does not establish runtime reachability or exploitability.',
          'Supply-chain checks inspect captured declarations and integrity metadata; private registries and intentional local dependencies still require trust review.',
          'Dependency cycles, orphan modules, coupling, and duplicated blocks are maintainability evidence. They are not security vulnerabilities by themselves.',
          'Dead-code and complexity results are bounded maintenance candidates. Dynamic imports, generated routes, framework conventions, and runtime registration can make apparently unused code reachable.',
          'Imported coverage artifacts describe a prior test run and do not prove which commit, environment, or security behavior was exercised.',
          'Secret files, Git history, symlinks, binary files, generated output and unsupported formats are excluded.',
          'Regex patterns can match comments and miss indirect flows; middleware, RLS and runtime policy need human review.',
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
        'Deterministic report saved. Findings remain review candidates.',
      );
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
    .addEdge('project_profile', 'web_posture')
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
        'web_posture',
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
    .addEdge('normalize', 'prepare_report')
    .addEdge('prepare_report', END)
    .compile();
}
