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
import {
  auditModes,
  severities,
  type AuditMode,
  type AuditOptions,
  type AuditReport,
  type Severity,
} from '../domain/types.ts';
import { executeAudit } from '../engine/run.ts';
import { scanOsv } from '../scanners/osv.ts';
import { renderDoctor, runDoctor } from './doctor.ts';
import { writeStaticReport } from '../reporting/static-report.ts';
import { startReportServer } from '../reporting/report-server.ts';
import { buildRuleQualityReport } from '../domain/rule-quality.ts';
import {
  applyReviewLedger,
  type PortableReviewDecision,
  upsertReviewLedger,
} from '../domain/review-ledger.ts';
import { parseReviewLedger } from '../domain/review-ledger-schema.ts';
import { buildPolicyResult, policyProfiles, type PolicyProfile } from '../domain/policy.ts';
import {
  applySuppressionLedger,
  type SuppressionLedger,
  upsertSuppressionLedger,
} from '../domain/suppression-ledger.ts';
import { parseSuppressionLedger } from '../domain/suppression-ledger-schema.ts';
import type { VerificationLedger } from '../domain/verification-ledger.ts';
import { parseVerificationLedger } from '../domain/verification-ledger-schema.ts';
import { renderCliHelp } from './help.ts';
import { initializeProjectConfig } from './init.ts';
import { createCliProgress } from './progress.ts';

disableRemoteTracing();
process.umask(0o077);
const config = configuration();
const arguments_ = process.argv.slice(2);
const [command, target] = arguments_;
const quiet = arguments_.includes('--quiet');
const verbose = arguments_.includes('--verbose');
const nonInteractive =
  arguments_.includes('--non-interactive') || ['1', 'true'].includes(process.env.CI ?? '');
const progress = createCliProgress(quiet, verbose);
const option = (name: string) => {
  const index = arguments_.indexOf(name);
  const value = index >= 0 ? arguments_[index + 1] : undefined;
  return value && !value.startsWith('--') ? value : undefined;
};
const commandModes = (): AuditMode[] | undefined => {
  const value = option('--modes');
  if (!value) return undefined;
  const selected = [...new Set(value.split(',').filter(Boolean))];
  const allowed = new Set<string>(auditModes);
  if (!selected.length || selected.some((mode) => !allowed.has(mode)))
    throw new Error(`Use --modes with: ${auditModes.join(', ')}.`);
  return selected as AuditMode[];
};
const commandAuditOptions = (): AuditOptions => {
  const url = option('--probe-url');
  const modes = commandModes();
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
    ...(modes ? { modes } : {}),
  };
};
const commandPort = (): number => {
  const value = option('--port');
  if (!value) return 4173;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65_535)
    throw new Error('Use --port with an integer from 0 to 65535.');
  return port;
};

async function openReport(location: string): Promise<void> {
  const reportServer = await startReportServer(location, commandPort());
  console.log(`Serving audit ${reportServer.reportPackage.report.auditId} at ${reportServer.url}`);
  console.log('Press Ctrl+C to stop.');
}
function render(report: AuditReport, format: string): string {
  if (
    ![
      'json',
      'md',
      'html',
      'sarif',
      'sbom',
      'bundle',
      'plan',
      'agent-plan',
      'rule-quality',
    ].includes(format)
  )
    throw new Error('Use json, md, html, sarif, sbom, bundle, plan, agent-plan, or rule-quality.');
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
                : format === 'rule-quality'
                  ? buildRuleQualityReport(report)
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
    throw new Error('Baseline report is not valid CodebaseScan JSON.');
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
    throw new Error('Audit report is not valid CodebaseScan JSON.');
  }
}

async function loadReviewLedger(file: string) {
  const resolved = path.resolve(file);
  const metadata = await stat(resolved);
  if (!metadata.isFile() || metadata.size > 2 * 1024 * 1024)
    throw new Error('Review ledger must be a regular JSON file no larger than 2 MB.');
  try {
    return parseReviewLedger(JSON.parse(await readFile(resolved, 'utf8')) as unknown);
  } catch {
    throw new Error('Review ledger is not valid CodebaseScan JSON.');
  }
}

async function loadSuppressionLedger(file: string): Promise<SuppressionLedger> {
  const resolved = path.resolve(file);
  const metadata = await stat(resolved);
  if (!metadata.isFile() || metadata.size > 2 * 1024 * 1024)
    throw new Error('Suppression ledger must be a regular JSON file no larger than 2 MB.');
  try {
    return parseSuppressionLedger(JSON.parse(await readFile(resolved, 'utf8')) as unknown);
  } catch {
    throw new Error('Suppression ledger is not valid CodebaseScan JSON.');
  }
}

async function loadVerificationLedger(file: string): Promise<VerificationLedger> {
  const resolved = path.resolve(file);
  const metadata = await stat(resolved);
  if (!metadata.isFile() || metadata.size > 2 * 1024 * 1024)
    throw new Error('Verification ledger must be a regular JSON file no larger than 2 MB.');
  try {
    return parseVerificationLedger(JSON.parse(await readFile(resolved, 'utf8')) as unknown);
  } catch {
    throw new Error('Verification ledger is not valid CodebaseScan JSON.');
  }
}

async function existingReviewLedger(file: string) {
  try {
    return await loadReviewLedger(file);
  } catch (error) {
    if (
      error instanceof Error &&
      'code' in error &&
      (error as NodeJS.ErrnoException).code === 'ENOENT'
    )
      return undefined;
    throw error;
  }
}

async function existingSuppressionLedger(file: string) {
  try {
    return await loadSuppressionLedger(file);
  } catch (error) {
    if (
      error instanceof Error &&
      'code' in error &&
      (error as NodeJS.ErrnoException).code === 'ENOENT'
    )
      return undefined;
    throw error;
  }
}

function portableReviewDecision(value: string | undefined): PortableReviewDecision {
  if (value === 'confirmed' || value === 'false_positive' || value === 'accepted_risk')
    return value;
  throw new Error('Use confirmed, false_positive, or accepted_risk for a portable review.');
}

async function defaultReviewLedgerDestination(location: string): Promise<string> {
  const resolved = path.resolve(location);
  const metadata = await stat(resolved);
  return metadata.isDirectory()
    ? path.join(resolved, 'review-ledger.json')
    : path.join(path.dirname(resolved), 'review-ledger.json');
}

async function defaultSuppressionLedgerDestination(location: string): Promise<string> {
  const resolved = path.resolve(location);
  const metadata = await stat(resolved);
  return metadata.isDirectory()
    ? path.join(resolved, 'suppression-ledger.json')
    : path.join(path.dirname(resolved), 'suppression-ledger.json');
}

async function preflight(root: string, requireApproval: boolean) {
  progress.phase('Inspecting project scope');
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
  if (!command || command === 'help' || command === '--help' || arguments_.includes('--help')) {
    console.log(renderCliHelp(command === 'help' ? target : command));
  } else if (command === 'init') {
    progress.phase('Creating declarative project configuration');
    const project = target && !target.startsWith('--') ? target : '.';
    const destination = await initializeProjectConfig(project, arguments_.includes('--force'));
    console.log(`Created ${destination}`);
  } else if (command === 'open') {
    if (nonInteractive)
      throw new Error('The report server is interactive. Remove --non-interactive and CI=true.');
    await openReport(target && !target.startsWith('--') ? target : 'codebasescan-report');
  } else if (command === 'doctor') {
    progress.phase('Checking local capabilities');
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
  } else if (
    command === 'review' &&
    target &&
    arguments_[2] &&
    arguments_[3] &&
    !arguments_[2].startsWith('--') &&
    !arguments_[3].startsWith('--')
  ) {
    const report = await loadReportArtifact(target);
    const destination = path.resolve(
      option('--output') ?? (await defaultReviewLedgerDestination(target)),
    );
    const note = option('--note');
    if (!note) throw new Error('Use --note with the evidence supporting this review decision.');
    const current = await existingReviewLedger(destination);
    const ledger = parseReviewLedger(
      upsertReviewLedger(current, report, {
        findingId: arguments_[2],
        decision: portableReviewDecision(arguments_[3]),
        note,
      }),
    );
    await writeFile(destination, `${JSON.stringify(ledger, null, 2)}\n`, { mode: 0o600 });
    console.log(`Saved review ledger ${destination}`);
  } else if (command === 'suppress' && target && arguments_[2] && !arguments_[2].startsWith('--')) {
    const report = await loadReportArtifact(target);
    const destination = path.resolve(
      option('--output') ?? (await defaultSuppressionLedgerDestination(target)),
    );
    const owner = option('--owner');
    const justification = option('--justification');
    const evidence = option('--evidence');
    const expiresAt = option('--expires-at');
    if (!owner || !justification || !evidence)
      throw new Error('Use --owner, --justification, and --evidence for a suppression.');
    const current = await existingSuppressionLedger(destination);
    const ledger = parseSuppressionLedger(
      upsertSuppressionLedger(current, report, {
        findingId: arguments_[2],
        owner,
        justification,
        evidence,
        ...(expiresAt ? { expiresAt } : {}),
      }),
    );
    await writeFile(destination, `${JSON.stringify(ledger, null, 2)}\n`, { mode: 0o600 });
    console.log(`Saved suppression ledger ${destination}`);
  } else if (command === 'finalize' && target) {
    const baselinePath = option('--baseline');
    const verificationPath = option('--verification');
    if (!baselinePath || !verificationPath)
      throw new Error('finalize requires --baseline and --verification.');
    const [after, baseline, verificationLedger] = await Promise.all([
      loadReportArtifact(target),
      loadBaseline(baselinePath),
      loadVerificationLedger(verificationPath),
    ]);
    if (baseline.projectName !== after.projectName)
      throw new Error('Baseline report belongs to a different project.');
    const policyName = option('--policy');
    if (policyName && !policyProfiles.includes(policyName as PolicyProfile))
      throw new Error('Use advisory, balanced, or strict for --policy.');
    const comparison = compareReports(baseline, after);
    const policyResult = buildPolicyResult(
      after,
      (policyName as PolicyProfile | undefined) ?? 'advisory',
      comparison,
    );
    const staticReport = await writeStaticReport(
      after,
      option('--report-dir') ?? path.resolve('codebasescan-final-report'),
      { baseline, policyResult, verificationLedger },
    );
    console.log(`Saved finalized report ${staticReport.directory}`);
    console.log(`Open ${staticReport.rootEntrypoint}`);
    console.error(
      `Baseline comparison: ${comparison.newFindings.length} new, ${comparison.resolvedFindings.length} resolved, ${comparison.unchangedFindings.length} unchanged.`,
    );
    process.exitCode = policyResult.exitCode;
    if (arguments_.includes('--open')) await openReport(path.dirname(staticReport.rootEntrypoint));
  } else if (command === 'audit') {
    if (nonInteractive && arguments_.includes('--open'))
      throw new Error('--open cannot be used with --non-interactive or CI=true.');
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-ci-'));
    const ciStore = new AuditStore(':memory:');
    try {
      const ciConfig = {
        ...config,
        dataDirectory: temporary,
        databasePath: ':memory:',
        checkpointPath: path.join(temporary, 'checkpoints.sqlite'),
        temporaryDirectory: path.join(temporary, 'scanner-staging'),
        scannerCacheDirectory: path.join(config.dataDirectory, 'scanner-cache'),
      };
      const auditTarget = target && !target.startsWith('--') ? target : '.';
      const root = await validateProjectRoot(auditTarget, temporary);
      const scopePreflight = await preflight(root, true);
      const project = ciStore.registerProject(path.basename(root), root);
      const audit = ciStore.enqueue(project.id, { ...commandAuditOptions(), scopePreflight });
      ciStore.claim(audit.id);
      progress.phase('Running deterministic scanners');
      await executeAudit(ciStore, audit.id, ciConfig, undefined, { humanReview: false });
      const completed = ciStore.audit(audit.id);
      if (completed.status !== 'completed' || !completed.report)
        throw new Error('Non-interactive audit did not produce a complete draft report.');
      const reviewsPath = option('--reviews');
      const reviewedReport = reviewsPath
        ? applyReviewLedger(completed.report, await loadReviewLedger(reviewsPath))
        : completed.report;
      const suppressionsPath = option('--suppressions');
      const report = suppressionsPath
        ? applySuppressionLedger(reviewedReport, await loadSuppressionLedger(suppressionsPath))
        : reviewedReport;
      progress.scanners(report.scanners);
      const threshold = option('--fail-on');
      if (threshold && !severities.includes(threshold as Severity))
        throw new Error('Use critical, high, medium, low, or info for --fail-on.');
      const policyName = option('--policy');
      if (policyName && !policyProfiles.includes(policyName as PolicyProfile))
        throw new Error('Use advisory, balanced, or strict for --policy.');
      if (policyName && threshold)
        throw new Error('Use either --policy or the compatibility --fail-on option, not both.');
      const baselinePath = option('--baseline');
      const baseline = baselinePath ? await loadBaseline(baselinePath) : null;
      if (baseline && baseline.projectName !== report.projectName)
        throw new Error('Baseline report belongs to a different project.');
      const comparison = baseline ? compareReports(baseline, report) : null;
      const policyResult = buildPolicyResult(
        report,
        (policyName as PolicyProfile | undefined) ?? 'advisory',
        comparison,
      );
      const gate = policyName
        ? { exitCode: policyResult.exitCode, gatedFindings: policyResult.summary.gatedFindings }
        : comparison
          ? baselineCiGate(comparison, threshold as Severity | undefined)
          : ciGate(report, threshold as Severity | undefined);
      const requestedFormat = option('--format');
      const destination = option('--output');
      if (arguments_.includes('--open') && (requestedFormat || destination))
        throw new Error('--open requires the default static report output.');
      let staticReportDirectory: string | undefined;
      if (!requestedFormat && !destination) {
        progress.phase('Writing immutable report package');
        const staticReport = await writeStaticReport(
          report,
          option('--report-dir') ?? path.resolve('codebasescan-report'),
          {
            ...(baseline ? { baseline } : {}),
            policyResult,
          },
        );
        staticReportDirectory = staticReport.directory;
        console.log(`Saved static report ${staticReport.directory}`);
        console.log(`Open ${staticReport.rootEntrypoint}`);
      } else {
        const format = requestedFormat ?? 'json';
        const output = render(report, format);
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
      if (policyName)
        console.error(
          `Policy ${policyResult.profile}: ${policyResult.decision}; ${policyResult.summary.gatedFindings} finding(s), ${policyResult.summary.blockingCoverageIssues} blocking coverage issue(s).`,
        );
      process.exitCode = gate.exitCode;
      if (arguments_.includes('--open') && staticReportDirectory)
        await openReport(path.dirname(staticReportDirectory));
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
      const extension = ['bundle', 'sbom', 'plan', 'agent-plan', 'rule-quality'].includes(format)
        ? `${format}.json`
        : format;
      const destination = path.resolve(`codebasescan-${report.auditId}.${extension}`);
      await writeFile(destination, render(report, format), { mode: 0o600, flag: 'wx' });
      console.log(`Saved ${destination}`);
    } else if (command === 'compare' && target && arguments_[2]) {
      const baseAudit = store.audit(target);
      const currentAudit = store.audit(arguments_[2]);
      const base = baseAudit.report;
      const current = currentAudit.report;
      if (!base || !current) throw new Error('Both audits must have reports before comparison.');
      const history = store
        .audits()
        .filter(
          (candidate) =>
            candidate.projectId === currentAudit.projectId &&
            candidate.id !== baseAudit.id &&
            candidate.id !== currentAudit.id &&
            candidate.createdAt < currentAudit.createdAt &&
            candidate.report,
        )
        .flatMap((candidate) => (candidate.report ? [candidate.report] : []));
      console.log(JSON.stringify(compareReports(base, current, history), null, 2));
    } else if (command === 'evaluate' && target) {
      const ids = arguments_.slice(1).filter((argument) => !argument.startsWith('--'));
      const reports = ids.map((id) => {
        const report = store!.audit(id).report;
        if (!report) throw new Error(`Audit ${id} has no report.`);
        return report;
      });
      console.log(JSON.stringify(evaluateReports(reports), null, 2));
    } else {
      const known = new Set([
        'register',
        'scan',
        'list',
        'export',
        'compare',
        'evaluate',
        'advisories',
        'task',
        'review',
        'suppress',
        'finalize',
      ]);
      if (known.has(command))
        throw new Error(`Missing or invalid arguments. Run codebasescan ${command} --help.`);
      throw new Error(`Unknown command "${command}". Run codebasescan --help.`);
    }
  }
} catch (error) {
  console.error(`Error: ${error instanceof Error ? error.message : 'Command failed.'}`);
  process.exitCode = command === 'audit' || command === 'finalize' ? 2 : 1;
} finally {
  store?.close();
}
