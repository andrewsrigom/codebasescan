import path from 'node:path';
import os from 'node:os';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { configuration } from '../server/config.ts';
import { AuditStore } from '../server/store.ts';
import { captureSnapshot, estimateProjectScope, validateProjectRoot } from '../security/paths.ts';
import { disableRemoteTracing } from '../security/privacy.ts';
import {
  toCycloneDx,
  toHtml,
  toInvestigationBundle,
  toMarkdown,
  toSarif,
} from '../domain/reports.ts';
import { compareReports } from '../domain/comparison.ts';
import { baselineCiGate, ciGate } from '../domain/ci.ts';
import { evaluateReports } from '../domain/evaluation.ts';
import { parseAuditReport } from '../domain/report-schema.ts';
import { buildRemediationPlan, buildRemediationTaskBundle } from '../domain/remediation.ts';
import { severities, type AuditOptions, type AuditReport, type Severity } from '../domain/types.ts';
import { executeAudit } from '../engine/run.ts';
import { scanOsv } from '../scanners/osv.ts';
import { renderDoctor, runDoctor } from './doctor.ts';
import { writeStaticReport } from '../reporting/static-report.ts';

disableRemoteTracing();
process.umask(0o077);
const config = configuration();
const arguments_ = process.argv.slice(2);
const [command, target] = arguments_;
const option = (name: string) => {
  const index = arguments_.indexOf(name);
  const value = index >= 0 ? arguments_[index + 1] : undefined;
  return value && !value.startsWith('--') ? value : undefined;
};
const commandAuditOptions = (): AuditOptions => {
  const url = option('--probe-url');
  return {
    ...(url
      ? {
          httpProbe: {
            url,
            allowPrivateNetwork: arguments_.includes('--allow-private-network'),
          },
        }
      : {}),
    ...(arguments_.includes('--secret-history') ? { gitHistorySecrets: true } : {}),
  };
};
function render(report: AuditReport, format: string): string {
  if (!['json', 'md', 'html', 'sarif', 'sbom', 'bundle', 'plan', 'agent-plan'].includes(format))
    throw new Error('Use json, md, html, sarif, sbom, bundle, plan, or agent-plan.');
  return format === 'html'
    ? toHtml(report)
    : format === 'md'
      ? toMarkdown(report)
      : JSON.stringify(
          format === 'sarif'
            ? toSarif(report)
            : format === 'sbom'
              ? toCycloneDx(report)
              : format === 'bundle'
                ? toInvestigationBundle(report)
                : format === 'plan' || format === 'agent-plan'
                  ? buildRemediationPlan(report)
                  : report,
          null,
          2,
        );
}

async function loadBaseline(file: string): Promise<AuditReport> {
  const resolved = path.resolve(file);
  const metadata = await stat(resolved);
  if (!metadata.isFile() || metadata.size > 16 * 1024 * 1024)
    throw new Error('Baseline report must be a regular JSON file no larger than 16 MB.');
  try {
    return parseAuditReport(JSON.parse(await readFile(resolved, 'utf8')) as unknown);
  } catch (error) {
    if (error instanceof Error && error.message.includes('Baseline report')) throw error;
    throw new Error('Baseline report is not valid Traceward JSON.');
  }
}

async function loadReportArtifact(location: string): Promise<AuditReport> {
  const resolved = path.resolve(location);
  const metadata = await stat(resolved);
  const file = metadata.isDirectory() ? path.join(resolved, 'audit-report.json') : resolved;
  const fileMetadata = metadata.isDirectory() ? await stat(file) : metadata;
  if (!fileMetadata.isFile() || fileMetadata.size > 16 * 1024 * 1024)
    throw new Error('Audit report must be a regular JSON file no larger than 16 MB.');
  try {
    return parseAuditReport(JSON.parse(await readFile(file, 'utf8')) as unknown);
  } catch {
    throw new Error('Audit report is not valid Traceward JSON.');
  }
}

async function preflight(root: string, requireApproval: boolean) {
  const estimate = await estimateProjectScope(root);
  const truncationApproved = arguments_.includes('--allow-partial-snapshot');
  const size = (estimate.supportedBytes / (1024 * 1024)).toFixed(2);
  console.error(
    `Scope estimate: ${estimate.supportedFiles} supported file(s), ${size} MiB, ${estimate.predictedTruncated ? 'partial snapshot expected' : 'within current limits'}.`,
  );
  if (requireApproval && estimate.predictedTruncated && !truncationApproved)
    throw new Error(
      `A partial snapshot is expected (${estimate.reasons.join(', ')}). Review the estimate and pass --allow-partial-snapshot to continue.`,
    );
  return { ...estimate, truncationApproved };
}

let store: AuditStore | null = null;
try {
  if (command === 'doctor') {
    const checks = await runDoctor(config);
    console.log(renderDoctor(checks));
    if (checks.some((check) => check.status === 'fail')) process.exitCode = 1;
  } else if (command === 'advisories' && target === 'update' && arguments_[2]) {
    const root = await validateProjectRoot(arguments_[2], config.dataDirectory);
    await preflight(root, true);
    const snapshot = await captureSnapshot(root);
    const result = await scanOsv(
      snapshot,
      true,
      config.advisoryDatabasePath,
      config.osvCacheHours,
      undefined,
      { forceRefresh: true },
    );
    if (result.run.status === 'failed') throw new Error(result.run.detail);
    console.log(
      `Updated ${config.advisoryDatabasePath} for ${result.dependencies.filter((item) => item.resolvedVersion).length} resolved package(s). ${result.findings.length} advisory match(es).`,
    );
  } else if (command === 'task' && target && arguments_[2] && !arguments_[2].startsWith('--')) {
    const report = await loadReportArtifact(target);
    const bundle = buildRemediationTaskBundle(report, arguments_[2]);
    const output = `${JSON.stringify(bundle, null, 2)}\n`;
    const destination = option('--output');
    if (destination) {
      const resolved = path.resolve(destination);
      await writeFile(resolved, output, { mode: 0o600, flag: 'wx' });
      console.log(`Saved ${resolved}`);
    } else console.log(output);
  } else if (command === 'audit') {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-ci-'));
    const ciStore = new AuditStore(':memory:');
    try {
      const ciConfig = {
        ...config,
        dataDirectory: temporary,
        databasePath: ':memory:',
        checkpointPath: path.join(temporary, 'checkpoints.sqlite'),
        temporaryDirectory: path.join(temporary, 'scanner-staging'),
      };
      const auditTarget = target && !target.startsWith('--') ? target : '.';
      const root = await validateProjectRoot(auditTarget, temporary);
      const scopePreflight = await preflight(root, true);
      const project = ciStore.registerProject(path.basename(root), root);
      const audit = ciStore.enqueue(project.id, { ...commandAuditOptions(), scopePreflight });
      ciStore.claim(audit.id);
      await executeAudit(ciStore, audit.id, ciConfig, undefined, { humanReview: false });
      const completed = ciStore.audit(audit.id);
      if (completed.status !== 'completed' || !completed.report)
        throw new Error('Non-interactive audit did not produce a complete draft report.');
      const threshold = option('--fail-on');
      if (threshold && !severities.includes(threshold as Severity))
        throw new Error('Use critical, high, medium, low, or info for --fail-on.');
      const baselinePath = option('--baseline');
      const baseline = baselinePath ? await loadBaseline(baselinePath) : null;
      if (baseline && baseline.projectName !== completed.report.projectName)
        throw new Error('Baseline report belongs to a different project.');
      const comparison = baseline ? compareReports(baseline, completed.report) : null;
      const gate = comparison
        ? baselineCiGate(comparison, threshold as Severity | undefined)
        : ciGate(completed.report, threshold as Severity | undefined);
      const requestedFormat = option('--format');
      const destination = option('--output');
      if (!requestedFormat && !destination) {
        const staticReport = await writeStaticReport(
          completed.report,
          option('--report-dir') ?? path.resolve('traceward-report'),
          baseline ? { baseline } : {},
        );
        console.log(`Saved static report ${staticReport.directory}`);
        console.log(`Open ${path.join(staticReport.directory, 'index.html')}`);
      } else {
        const format = requestedFormat ?? 'json';
        const output = render(completed.report, format);
        if (destination) {
          const resolved = path.resolve(destination);
          await writeFile(resolved, output, { mode: 0o600, flag: 'wx' });
          console.error(`Saved ${resolved}`);
        } else console.log(output);
      }
      if (comparison)
        console.error(
          `Baseline comparison: ${comparison.newFindings.length} new, ${comparison.resolvedFindings.length} resolved, ${comparison.unchangedFindings.length} unchanged.`,
        );
      if (threshold)
        console.error(
          `Severity gate ${threshold}: ${gate.gatedFindings} ${comparison ? 'new' : 'unresolved'} finding(s) at or above threshold.`,
        );
      process.exitCode = gate.exitCode;
    } finally {
      ciStore.close();
      await rm(temporary, { recursive: true, force: true });
    }
  } else {
    store = new AuditStore(config.databasePath);
    if ((command === 'register' || command === 'scan') && target) {
      const root = await validateProjectRoot(target, config.dataDirectory);
      const scopePreflight = await preflight(root, command === 'scan');
      const project = store.registerProject(path.basename(root), root);
      if (command === 'register') console.log(JSON.stringify(project, null, 2));
      else {
        const audit = store.enqueue(project.id, { ...commandAuditOptions(), scopePreflight });
        console.log(
          `Queued ${audit.id}. Run npm run worker to process it, then review the report in the local UI.`,
        );
      }
    } else if (command === 'list') {
      console.log(
        JSON.stringify(
          store.audits().map((audit) => ({
            id: audit.id,
            projectId: audit.projectId,
            status: audit.status,
            createdAt: audit.createdAt,
            updatedAt: audit.updatedAt,
          })),
          null,
          2,
        ),
      );
    } else if (command === 'export' && target) {
      const report = store.audit(target).report;
      if (!report) throw new Error('No report is available for this audit.');
      const format = arguments_[2] ?? 'json';
      const extension = ['bundle', 'sbom', 'plan', 'agent-plan'].includes(format)
        ? `${format}.json`
        : format;
      const destination = path.resolve(`traceward-${report.auditId}.${extension}`);
      await writeFile(destination, render(report, format), { mode: 0o600, flag: 'wx' });
      console.log(`Saved ${destination}`);
    } else if (command === 'compare' && target && arguments_[2]) {
      const base = store.audit(target).report;
      const current = store.audit(arguments_[2]).report;
      if (!base || !current) throw new Error('Both audits must have reports before comparison.');
      console.log(JSON.stringify(compareReports(base, current), null, 2));
    } else if (command === 'evaluate' && target) {
      const ids = arguments_.slice(1).filter((argument) => !argument.startsWith('--'));
      const reports = ids.map((id) => {
        const report = store!.audit(id).report;
        if (!report) throw new Error(`Audit ${id} has no report.`);
        return report;
      });
      console.log(JSON.stringify(evaluateReports(reports), null, 2));
    } else {
      console.log(
        'Traceward\n\n  npm run cli -- audit [project] [--report-dir traceward-report] [--secret-history] [--allow-partial-snapshot] [--baseline previous.json] [--fail-on high]\n  npm run cli -- audit [project] --format json|sarif|sbom|md|html|bundle|agent-plan [--output report.json]\n  npm run cli -- task <report-directory|audit-report.json> <task-id> [--output task.json]\n  npm run cli -- doctor\n  npm run cli -- advisories update /path/to/project\n  npm run cli -- register /path/to/project\n  npm run cli -- scan /path/to/project [--secret-history] [--allow-partial-snapshot] [--probe-url http://127.0.0.1:3000/] [--allow-private-network]\n  npm run cli -- list\n  npm run cli -- compare <base-audit-id> <current-audit-id>\n  npm run cli -- evaluate <audit-id> [more-audit-ids...]\n  npm run cli -- export <audit-id> json|md|html|sarif|sbom|bundle|agent-plan',
      );
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Command failed.');
  process.exitCode = command === 'audit' ? 2 : 1;
} finally {
  store?.close();
}
