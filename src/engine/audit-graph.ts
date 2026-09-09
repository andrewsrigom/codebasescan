import { Annotation, END, START, StateGraph, interrupt } from '@langchain/langgraph';
import type { BaseCheckpointSaver } from '@langchain/langgraph-checkpoint';
import type { AuditReport, Dependency, Finding, ScannerRun, Snapshot } from '../domain/types.ts';
import { mergeFindings } from '../domain/findings.ts';
import { scanPatterns } from '../scanners/builtin.ts';
import { inventory } from '../scanners/inventory.ts';
import { scanExternal } from '../scanners/external.ts';
import { captureSnapshot, redactedSnapshot } from '../security/paths.ts';
import type { Configuration } from '../server/config.ts';
import type { AuditStore } from '../server/store.ts';
import type { Reviewer } from './model.ts';
import { buildReviewGraph } from './review-graph.ts';
const mergeRuns = (left: ScannerRun[], right: ScannerRun[]) => [...new Map([...left, ...right].map((run) => [run.id, run])).values()];
export const AuditState = Annotation.Root({
  auditId: Annotation<string>(),
  snapshotDigest: Annotation<string>({ reducer: (_, value) => value, default: () => '' }),
  fileCount: Annotation<number>({ reducer: (_, value) => value, default: () => 0 }),
  skipped: Annotation<Record<string, number>>({ reducer: (_, value) => value, default: () => ({}) }),
  truncated: Annotation<boolean>({ reducer: (_, value) => value, default: () => false }),
  findings: Annotation<Finding[]>({ reducer: mergeFindings, default: () => [] }),
  scanners: Annotation<ScannerRun[]>({ reducer: mergeRuns, default: () => [] }),
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
  signal?: AbortSignal;
}) {
  const { root, projectName, config, store, checkpointer, reviewer, signal } = options;
  let captured: Promise<Snapshot> | null = null;
  const snapshot = () => captured ??= captureSnapshot(root);
  const event = (state: State, stage: string, message: string) => store.event(state.auditId, stage, stage, message);
  const checkedSnapshot = async (state: State) => {
    signal?.throwIfAborted();
    const source = await snapshot();
    if (state.snapshotDigest && state.snapshotDigest !== source.digest)
      throw new Error('Source changed after the checkpoint. Start a new audit; evidence from different snapshots will not be mixed.');
    return source;
  };
  return new StateGraph(AuditState)
    .addNode('snapshot', async (state) => {
      const source = await snapshot();
      event(state, 'snapshot', `Captured ${source.files.length} files without running the target project.`);
      return { snapshotDigest: source.digest, fileCount: source.files.length, skipped: source.skipped, truncated: source.truncated };
    })
    .addNode('patterns', async (state) => {
      const started = Date.now();
      const source = await checkedSnapshot(state);
      const findings = scanPatterns(source);
      event(state, 'patterns', `${findings.length} deterministic review candidates. None are automatically confirmed.`);
      return { findings, scanners: [{ id: 'builtin', name: 'Built-in patterns', status: findings.length >= 300 || source.truncated ? 'partial' : 'completed', durationMs: Date.now() - started, findings: findings.length, detail: 'Seven bounded regex heuristics. Not a complete SAST engine or interprocedural analysis.', version: '0.1.0' } satisfies ScannerRun] };
    })
    .addNode('semgrep', async (state) => {
      const result = await scanExternal('semgrep', await checkedSnapshot(state), config.semgrep, config.temporaryDirectory, config.rulesDirectory, signal);
      event(state, 'semgrep', `Semgrep: ${result.run.status}.`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('gitleaks', async (state) => {
      const result = await scanExternal('gitleaks', await checkedSnapshot(state), config.gitleaks, config.temporaryDirectory, config.rulesDirectory, signal);
      event(state, 'gitleaks', `Gitleaks: ${result.run.status}.`);
      return { findings: result.findings, scanners: [result.run] };
    })
    .addNode('inventory', async (state) => {
      const dependencies = inventory(await checkedSnapshot(state));
      event(state, 'inventory', `Collected ${dependencies.length} manifest declarations. Vulnerability matching is not implemented.`);
      return { dependencies, scanners: [{ id: 'dependency-matching', name: 'Dependency vulnerabilities', status: 'skipped', durationMs: 0, findings: 0, detail: 'Manifest inventory only. OSV/Trivy vulnerability matching and database freshness are a planned extension.' } satisfies ScannerRun] };
    })
    .addNode('normalize', (state) => {
      event(state, 'normalize', `Normalized ${state.findings.length} candidates. Cross-scanner candidates are retained separately.`);
      return {};
    })
    .addNode('investigate', async (state) => {
      const finding = state.findings[state.cursor];
      if (!finding)
        return {};
      const source = redactedSnapshot(await checkedSnapshot(state));
      const graph = buildReviewGraph(source, reviewer, signal);
      const result = await graph.invoke({ finding }, { signal, recursionLimit: 12 });
      const reviewed = { ...finding, ...(result.analysis ? { analysis: result.analysis } : {}) };
      store.event(state.auditId, `investigate:${finding.id}`, 'investigate', `Reviewed ${finding.ruleId}; source disposition remains ${finding.disposition}.`);
      return { analyzed: [reviewed], cursor: state.cursor + 1 };
    })
    .addNode('prepare_report', (state) => {
      const findings = mergeFindings(state.findings, state.analyzed);
      const report: AuditReport = {
        schemaVersion: 1, auditId: state.auditId, projectName, createdAt: new Date().toISOString(),
        snapshotDigest: state.snapshotDigest, filesAnalyzed: state.fileCount,
        skipped: state.skipped, truncated: state.truncated, aiMode: config.aiMode,
        findings, scanners: state.scanners, dependencies: state.dependencies, publication: 'draft',
        limitations: [
          'This is a bounded static review, not a pentest, compliance audit, or security certification.',
          'No target code, package lifecycle script, exploit, or network probe is executed.',
          'AI assessments cannot confirm findings, lower scanner severity, or suppress candidates automatically.',
          'Dependency versions are manifest requests, not resolved installations or vulnerability matches.',
          'Secret files, Git history, symlinks, binary files, generated output and unsupported formats are excluded.',
          'Regex patterns can match comments and miss indirect flows; middleware, RLS and runtime policy need human review.',
          ...(state.findings.length > maximumAnalyzedFindings ? [`Contextual analysis was limited to ${maximumAnalyzedFindings} candidates. Remaining candidates are preserved without contextual assessment.`] : []),
          ...(state.truncated ? ['The source snapshot was truncated. Review skipped files before relying on coverage.'] : []),
        ],
      };
      store.saveProgress(state.auditId, report);
      event(state, 'prepare_report', 'Draft report saved. Waiting for an analyst to review publication.');
      return { report };
    })
    .addNode('human_review', () => {
      const decision = interrupt({ kind: 'publication_review', message: 'Review the evidence before publishing. Publishing does not confirm unresolved findings.' }) as {
        note?: unknown;
      };
      if (typeof decision?.note !== 'string' || decision.note.trim().length < 12)
        throw new Error('A publication review note is required.');
      return { reviewNote: decision.note.trim().slice(0, 2000) };
    })
    .addNode('publish', (state) => {
      if (!state.report)
        throw new Error('No report was prepared.');
      const latest = store.audit(state.auditId).report;
      const report: AuditReport = { ...state.report, findings: latest?.findings ?? state.report.findings, publication: 'reviewed', reviewNote: state.reviewNote };
      store.saveProgress(state.auditId, report);
      event(state, 'publish', 'Report published with review dispositions and limitations intact.');
      return { report };
    })
    .addEdge(START, 'snapshot')
    .addEdge('snapshot', 'patterns')
    .addEdge('snapshot', 'semgrep')
    .addEdge('snapshot', 'gitleaks')
    .addEdge('snapshot', 'inventory')
    .addEdge(['patterns', 'semgrep', 'gitleaks', 'inventory'], 'normalize')
    .addConditionalEdges('normalize', (state) => state.findings.length ? 'investigate' : 'prepare_report')
    .addConditionalEdges('investigate', (state) => state.cursor < Math.min(state.findings.length, maximumAnalyzedFindings) ? 'investigate' : 'prepare_report')
    .addEdge('prepare_report', 'human_review')
    .addEdge('human_review', 'publish')
    .addEdge('publish', END)
    .compile({ checkpointer });
}
