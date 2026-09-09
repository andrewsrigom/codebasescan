import { Annotation, END, START, StateGraph, interrupt } from '@langchain/langgraph';
import type { BaseCheckpointSaver } from '@langchain/langgraph-checkpoint';
import type {
  AuditReport,
  Dependency,
  Finding,
  HttpProbeOptions,
  HttpProbeReport,
  ScannerRun,
  Snapshot,
} from '../domain/types.ts';
import { mergeFindings } from '../domain/findings.ts';
import { buildCoverage } from '../domain/coverage.ts';
import { attachProvenance } from '../domain/provenance.ts';
import { scanPatterns } from '../scanners/builtin.ts';
import { scanPosture } from '../scanners/posture.ts';
import path from 'node:path';
import { scanExternal } from '../scanners/external.ts';
import { probeHttp, reconcileHttpPosture, skippedHttpProbe } from '../scanners/http-probe.ts';
import { scanOsv } from '../scanners/osv.ts';
import { captureSnapshot, redactedSnapshot } from '../security/paths.ts';
import type { Configuration } from '../server/config.ts';
import type { AuditStore } from '../server/store.ts';
import type { Reviewer } from './model.ts';
import { buildReviewGraph } from './review-graph.ts';
const mergeRuns = (left: ScannerRun[], right: ScannerRun[]) => [
  ...new Map([...left, ...right].map((run) => [run.id, run])).values(),
];
export const AuditState = Annotation.Root({
  auditId: Annotation<string>(),
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
  analyzed: Annotation<Finding[]>({ reducer: mergeFindings, default: () => [] }),
  cursor: Annotation<number>({ reducer: (_, value) => value, default: () => 0 }),
  reviewNote: Annotation<string>({ reducer: (_, value) => value, default: () => '' }),
  report: Annotation<AuditReport | null>({ reducer: (_, value) => value, default: () => null }),
});
type State = typeof AuditState.State;
const maximumAnalyzedFindings = 12;
export function buildAuditGraph(options: {
  root: string;
  projectName: string;
  config: Configuration;
  store: AuditStore;
  checkpointer: BaseCheckpointSaver;
  reviewer: Reviewer | null;
  httpProbe?: HttpProbeOptions;
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
    humanReview = true,
    signal,
  } = options;
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
      const started = Date.now();
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
            durationMs: Date.now() - started,
            findings: findings.length,
            detail:
              'Seven bounded regex heuristics. Not a complete SAST engine or interprocedural analysis.',
            version: '0.2.0',
          } satisfies ScannerRun,
        ],
      };
    })
    .addNode('posture', async (state) => {
      const started = Date.now();
      const source = await checkedSnapshot(state);
      const findings = scanPosture(source);
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
            durationMs: Date.now() - started,
            findings: findings.length,
            detail:
              'Conservative checks for security headers, session cookies, CORS, route and server-action authorization, and environment configuration in TypeScript/Node.js/Next.js projects.',
            version: '0.2.0',
          } satisfies ScannerRun,
        ],
      };
    })
    .addNode('semgrep', async (state) => {
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
      const result = await scanExternal(
        'gitleaks',
        await checkedSnapshot(state),
        config.gitleaks,
        config.temporaryDirectory,
        config.rulesDirectory,
        signal,
      );
      event(state, 'gitleaks', `Gitleaks: ${result.run.status}.`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('http_probe', async (state) => {
      const result = httpProbe ? await probeHttp(httpProbe, signal) : skippedHttpProbe();
      event(state, 'http_probe', `HTTP runtime posture: ${result.run.status}.`);
      return {
        findings: result.findings,
        scanners: [result.run],
        httpProbe: result.report ?? null,
      };
    })
    .addNode('inventory', async (state) => {
      const result = await scanOsv(
        await checkedSnapshot(state),
        config.osv,
        path.join(config.dataDirectory, 'osv-cache.json'),
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
      const normalizedFindings = reconcileHttpPosture(state.findings, state.httpProbe ?? undefined);
      event(
        state,
        'normalize',
        `Normalized ${normalizedFindings.length} candidates. Related static and observed HTTP posture evidence was reconciled without discarding either evidence source.`,
      );
      return { normalizedFindings };
    })
    .addNode('investigate', async (state) => {
      const finding = state.normalizedFindings[state.cursor];
      if (!finding) return {};
      const source = redactedSnapshot(await checkedSnapshot(state));
      const graph = buildReviewGraph(source, reviewer, signal);
      const result = await graph.invoke({ finding }, { signal, recursionLimit: 12 });
      const reviewed = { ...finding, ...(result.analysis ? { analysis: result.analysis } : {}) };
      store.event(
        state.auditId,
        `investigate:${finding.id}`,
        'investigate',
        `Reviewed ${finding.ruleId}; source disposition remains ${finding.disposition}.`,
      );
      return { analyzed: [reviewed], cursor: state.cursor + 1 };
    })
    .addNode('prepare_report', (state) => {
      const createdAt = new Date().toISOString();
      const findings = attachProvenance(
        mergeFindings(state.normalizedFindings, state.analyzed),
        state.scanners,
        createdAt,
      );
      const modelAnalyses = findings.flatMap((finding) =>
        finding.analysis?.provider ? [finding.analysis] : [],
      );
      const storedUsage = store.aiUsage(state.auditId);
      const report: AuditReport = {
        schemaVersion: 2,
        auditId: state.auditId,
        projectName,
        createdAt,
        snapshotDigest: state.snapshotDigest,
        filesAnalyzed: state.fileCount,
        skipped: state.skipped,
        truncated: state.truncated,
        aiMode: config.aiMode,
        findings,
        scanners: state.scanners,
        dependencies: state.dependencies,
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
          'Secret files, Git history, symlinks, binary files, generated output and unsupported formats are excluded.',
          'Regex patterns can match comments and miss indirect flows; middleware, RLS and runtime policy need human review.',
          ...(state.normalizedFindings.length > maximumAnalyzedFindings
            ? [
                `Contextual analysis was limited to ${maximumAnalyzedFindings} candidates. Remaining candidates are preserved without contextual assessment.`,
              ]
            : []),
          ...(state.truncated
            ? [
                'The source snapshot was truncated. Review skipped files before relying on coverage.',
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
        publication: 'reviewed',
        reviewNote: state.reviewNote,
      };
      store.saveProgress(state.auditId, report);
      event(state, 'publish', 'Report published with review dispositions and limitations intact.');
      return { report };
    })
    .addEdge(START, 'snapshot')
    .addEdge('snapshot', 'patterns')
    .addEdge('snapshot', 'posture')
    .addEdge('snapshot', 'semgrep')
    .addEdge('snapshot', 'gitleaks')
    .addEdge('snapshot', 'http_probe')
    .addEdge('snapshot', 'inventory')
    .addEdge(['patterns', 'posture', 'semgrep', 'gitleaks', 'http_probe', 'inventory'], 'normalize')
    .addConditionalEdges('normalize', (state) =>
      state.normalizedFindings.length ? 'investigate' : 'prepare_report',
    )
    .addConditionalEdges('investigate', (state) =>
      state.cursor < Math.min(state.normalizedFindings.length, maximumAnalyzedFindings)
        ? 'investigate'
        : 'prepare_report',
    )
    .addConditionalEdges('prepare_report', () => (humanReview ? 'human_review' : END))
    .addEdge('human_review', 'publish')
    .addEdge('publish', END)
    .compile({ checkpointer });
}
