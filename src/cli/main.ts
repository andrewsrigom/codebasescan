import path from 'node:path';
import os from 'node:os';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { configuration } from '../server/config.ts';
import { AuditStore } from '../server/store.ts';
import { validateProjectRoot } from '../security/paths.ts';
import { disableRemoteTracing } from '../security/privacy.ts';
import { toHtml, toInvestigationBundle, toMarkdown, toSarif } from '../domain/reports.ts';
import { compareReports } from '../domain/comparison.ts';
import { baselineCiGate, ciGate } from '../domain/ci.ts';
import { evaluateReports } from '../domain/evaluation.ts';
import { parseAuditReport } from '../domain/report-schema.ts';
import { severities, type AuditOptions, type AuditReport, type Severity } from '../domain/types.ts';
import { executeAudit } from '../engine/run.ts';

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
const probeOptions = (): AuditOptions => {
  const url = option('--probe-url');
  return url
    ? {
        httpProbe: {
          url,
          allowPrivateNetwork: arguments_.includes('--allow-private-network'),
        },
      }
    : {};
};
function render(report: AuditReport, format: string): string {
  if (!['json', 'md', 'html', 'sarif', 'bundle'].includes(format))
    throw new Error('Use json, md, html, sarif, or bundle.');
  return format === 'html'
    ? toHtml(report)
    : format === 'md'
      ? toMarkdown(report)
      : JSON.stringify(
          format === 'sarif'
            ? toSarif(report)
            : format === 'bundle'
              ? toInvestigationBundle(report)
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

let store: AuditStore | null = null;
try {
  if (command === 'audit' && target) {
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
      const root = await validateProjectRoot(target, temporary);
      const project = ciStore.registerProject(path.basename(root), root);
      const audit = ciStore.enqueue(project.id, probeOptions());
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
      const format = option('--format') ?? 'json';
      const output = render(completed.report, format);
      const destination = option('--output');
      if (destination) {
        const resolved = path.resolve(destination);
        await writeFile(resolved, output, { mode: 0o600, flag: 'wx' });
        console.error(`Saved ${resolved}`);
      } else console.log(output);
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
      const project = store.registerProject(path.basename(root), root);
      if (command === 'register') console.log(JSON.stringify(project, null, 2));
      else {
        const audit = store.enqueue(project.id, probeOptions());
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
      const destination = path.resolve(
        `traceward-${report.auditId}.${format === 'bundle' ? 'bundle.json' : format}`,
      );
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
        'Traceward\n\n  npm run cli -- audit /path/to/project [--baseline previous.json] [--fail-on high] [--format json|sarif|md|html|bundle] [--output report.json]\n  npm run cli -- register /path/to/project\n  npm run cli -- scan /path/to/project [--probe-url http://127.0.0.1:3000/] [--allow-private-network]\n  npm run cli -- list\n  npm run cli -- compare <base-audit-id> <current-audit-id>\n  npm run cli -- evaluate <audit-id> [more-audit-ids...]\n  npm run cli -- export <audit-id> json|md|html|sarif|bundle',
      );
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Command failed.');
  process.exitCode = command === 'audit' ? 2 : 1;
} finally {
  store?.close();
}
