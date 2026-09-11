import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import type { AuditReport } from '../domain/types.ts';
import { digest } from '../domain/findings.ts';
import { maximumAuditReportBytes } from './limits.ts';
import { parseAuditReport } from '../domain/report-schema.ts';
import {
  toCycloneDx,
  toHtml,
  toInvestigationBundle,
  toMarkdown,
  toSarif,
} from '../domain/reports.ts';
import { buildRemediationPlan, buildRemediationResult } from '../domain/remediation.ts';
import {
  parseRemediationPlan,
  parseRemediationResult,
  remediationPlanJsonSchema,
  remediationResultJsonSchema,
} from '../domain/remediation-schema.ts';
import { buildRuleQualityReport } from '../domain/rule-quality.ts';
import { parseRuleQualityReport, ruleQualityJsonSchema } from '../domain/rule-quality-schema.ts';
import { reviewLedgerJsonSchema } from '../domain/review-ledger-schema.ts';
import { buildRunManifest, type RunManifestOutput } from '../domain/run-manifest.ts';
import { parseRunManifest, runManifestJsonSchema } from '../domain/run-manifest-schema.ts';
import { buildPolicyResult, type PolicyResult } from '../domain/policy.ts';
import { parsePolicyResult, policyResultJsonSchema } from '../domain/policy-schema.ts';
import { suppressionLedgerJsonSchema } from '../domain/suppression-ledger-schema.ts';
import type { VerificationLedger } from '../domain/verification-ledger.ts';
import { verificationLedgerJsonSchema } from '../domain/verification-ledger-schema.ts';
import {
  calibrationLedgerJsonSchema,
  calibrationReportJsonSchema,
} from '../domain/calibration-schema.ts';
import { buildAgentReport } from '../domain/agent-report.ts';
import { agentReportJsonSchema, parseAgentReport } from '../domain/agent-report-schema.ts';
import {
  agentReviewRulePack,
  agentReviewRulePackJsonSchema,
  parseAgentReviewRulePack,
} from '../domain/agent-rules.ts';

export const staticReportVersion = 1 as const;

export interface StaticReportManifest {
  schemaVersion: typeof staticReportVersion;
  kind: 'codebasescan-static-report';
  auditId: string;
  snapshotDigest: string;
  generatedAt: string;
  entrypoint: 'index.html';
  files: {
    path: string;
    mediaType: string;
    bytes: number;
    sha256: string;
  }[];
}

export interface StaticReportOptions {
  baseline?: AuditReport;
  policyResult?: PolicyResult;
  verificationLedger?: VerificationLedger;
}

export const staticReportIndexVersion = 1 as const;

export interface StaticReportIndexEntry {
  auditId: string;
  projectName: string;
  generatedAt: string;
  directory: string;
  publication: AuditReport['publication'];
  findings: {
    total: number;
    critical: number;
    high: number;
  };
  coverage: {
    complete: number;
    partial: number;
  };
}

export interface StaticReportIndex {
  schemaVersion: typeof staticReportIndexVersion;
  kind: 'codebasescan-report-index';
  generatedAt: string;
  latestAuditId: string;
  audits: StaticReportIndexEntry[];
}

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

interface StaticArtifact {
  path: string;
  mediaType: string;
  content: string;
}

function describeArtifact(artifact: StaticArtifact): RunManifestOutput {
  return {
    path: artifact.path,
    mediaType: artifact.mediaType,
    bytes: Buffer.byteLength(artifact.content),
    sha256: digest(artifact.content),
  };
}

function safeAuditSegment(auditId: string): string {
  if (!/^[a-zA-Z0-9-]{1,100}$/.test(auditId))
    throw new Error('Audit ID cannot be used as a report directory name.');
  return auditId;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function reportIndexEntry(report: AuditReport): StaticReportIndexEntry {
  return {
    auditId: report.auditId,
    projectName: report.projectName,
    generatedAt: report.createdAt,
    directory: safeAuditSegment(report.auditId),
    publication: report.publication,
    findings: {
      total: report.findings.length,
      critical: report.findings.filter((finding) => finding.severity === 'critical').length,
      high: report.findings.filter((finding) => finding.severity === 'high').length,
    },
    coverage: {
      complete:
        report.coverage?.filter((capability) => capability.status === 'COMPLETE').length ?? 0,
      partial: report.coverage?.filter((capability) => capability.status === 'PARTIAL').length ?? 0,
    },
  };
}

async function readIndexedReport(directory: string): Promise<AuditReport | null> {
  try {
    const manifestFile = path.join(directory, 'manifest.json');
    const manifestMetadata = await lstat(manifestFile);
    if (
      !manifestMetadata.isFile() ||
      manifestMetadata.isSymbolicLink() ||
      manifestMetadata.size > 1024 * 1024
    )
      return null;
    const manifestValue: unknown = JSON.parse(await readFile(manifestFile, 'utf8'));
    if (
      !isRecord(manifestValue) ||
      manifestValue.schemaVersion !== staticReportVersion ||
      manifestValue.kind !== 'codebasescan-static-report' ||
      !Array.isArray(manifestValue.files)
    )
      return null;
    const auditArtifact = manifestValue.files.find(
      (value): value is Record<string, unknown> =>
        isRecord(value) && value.path === 'audit-report.json',
    );
    if (
      !auditArtifact ||
      typeof auditArtifact.bytes !== 'number' ||
      auditArtifact.bytes < 0 ||
      auditArtifact.bytes > maximumAuditReportBytes ||
      typeof auditArtifact.sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(auditArtifact.sha256)
    )
      return null;
    const reportFile = path.join(directory, 'audit-report.json');
    const reportMetadata = await lstat(reportFile);
    if (
      !reportMetadata.isFile() ||
      reportMetadata.isSymbolicLink() ||
      reportMetadata.size !== auditArtifact.bytes
    )
      return null;
    const content = await readFile(reportFile, 'utf8');
    if (digest(content) !== auditArtifact.sha256) return null;
    const report = parseAuditReport(JSON.parse(content) as unknown);
    return manifestValue.auditId === report.auditId &&
      manifestValue.generatedAt === report.createdAt
      ? report
      : null;
  } catch {
    return null;
  }
}

async function readStoredIndexEntry(directory: string): Promise<StaticReportIndexEntry | null> {
  try {
    const manifestFile = path.join(directory, 'manifest.json');
    const manifestMetadata = await lstat(manifestFile);
    if (
      !manifestMetadata.isFile() ||
      manifestMetadata.isSymbolicLink() ||
      manifestMetadata.size > 1024 * 1024
    )
      return null;
    const manifestValue: unknown = JSON.parse(await readFile(manifestFile, 'utf8'));
    if (
      !isRecord(manifestValue) ||
      manifestValue.schemaVersion !== staticReportVersion ||
      manifestValue.kind !== 'codebasescan-static-report' ||
      !Array.isArray(manifestValue.files)
    )
      return null;
    const indexArtifact = manifestValue.files.find(
      (value): value is Record<string, unknown> =>
        isRecord(value) && value.path === 'report-index-entry.json',
    );
    if (
      !indexArtifact ||
      typeof indexArtifact.bytes !== 'number' ||
      indexArtifact.bytes < 1 ||
      indexArtifact.bytes > 16 * 1024 ||
      typeof indexArtifact.sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(indexArtifact.sha256)
    )
      return null;
    const entryFile = path.join(directory, 'report-index-entry.json');
    const entryMetadata = await lstat(entryFile);
    if (
      !entryMetadata.isFile() ||
      entryMetadata.isSymbolicLink() ||
      entryMetadata.size !== indexArtifact.bytes
    )
      return null;
    const content = await readFile(entryFile, 'utf8');
    if (digest(content) !== indexArtifact.sha256) return null;
    const entry: unknown = JSON.parse(content);
    return isIndexEntry(entry) && entry.auditId === path.basename(directory) ? entry : null;
  } catch {
    return null;
  }
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );
}

export function renderStaticReportIndex(index: StaticReportIndex): string {
  const rows = index.audits
    .map(
      (audit, position) => `
        <li>
          <a href="./${audit.directory}/index.html">
            <span><strong>${escapeHtml(audit.projectName)}</strong><small>${escapeHtml(audit.generatedAt)} · ${escapeHtml(audit.publication)}${position === 0 ? ' · latest' : ''}</small></span>
            <span class="numbers"><strong>${audit.findings.total}</strong><small>findings · ${audit.findings.critical} critical · ${audit.findings.high} high</small></span>
          </a>
        </li>`,
    )
    .join('');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
  <title>CodebaseScan audit history</title>
  <style>
    :root{color-scheme:dark;font-family:ui-sans-serif,system-ui,sans-serif;background:#080b14;color:#eef2ff}*{box-sizing:border-box}body{margin:0}main{width:min(980px,calc(100% - 32px));margin:64px auto}header{margin-bottom:28px}p,small{color:#96a0b8}.eyebrow{color:#4f8cff;font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}h1{font-size:clamp(32px,5vw,54px);margin:8px 0 12px}ul{list-style:none;padding:0;margin:0;border:1px solid #252b3d;border-radius:14px;overflow:hidden;background:#101522}li+li{border-top:1px solid #252b3d}a{display:flex;justify-content:space-between;gap:24px;padding:22px;color:inherit;text-decoration:none}a:hover{background:#151c2e}span{display:grid;gap:6px}.numbers{text-align:right}small{font-size:12px;font-weight:400}@media(max-width:620px){main{margin:32px auto}a{display:grid}.numbers{text-align:left}}
  </style>
</head>
<body>
  <main>
    <header><div class="eyebrow">CodebaseScan</div><h1>Audit history</h1><p>The newest result stays at this address. Every audit remains available as an immutable package.</p></header>
    <ul>${rows}</ul>
  </main>
</body>
</html>`;
}

function isIndexEntry(value: unknown): value is StaticReportIndexEntry {
  return (
    isRecord(value) &&
    typeof value.auditId === 'string' &&
    /^[A-Za-z0-9-]{1,100}$/.test(value.auditId) &&
    typeof value.projectName === 'string' &&
    value.projectName.length > 0 &&
    value.projectName.length <= 200 &&
    typeof value.generatedAt === 'string' &&
    !Number.isNaN(Date.parse(value.generatedAt)) &&
    value.directory === value.auditId &&
    (value.publication === 'draft' || value.publication === 'reviewed') &&
    isRecord(value.findings) &&
    Number.isInteger(value.findings.total) &&
    Number.isInteger(value.findings.critical) &&
    Number.isInteger(value.findings.high) &&
    isRecord(value.coverage) &&
    Number.isInteger(value.coverage.complete) &&
    Number.isInteger(value.coverage.partial)
  );
}

export function parseStaticReportIndex(value: unknown): StaticReportIndex {
  if (
    !isRecord(value) ||
    value.schemaVersion !== staticReportIndexVersion ||
    value.kind !== 'codebasescan-report-index' ||
    typeof value.generatedAt !== 'string' ||
    Number.isNaN(Date.parse(value.generatedAt)) ||
    typeof value.latestAuditId !== 'string' ||
    !Array.isArray(value.audits) ||
    value.audits.length < 1 ||
    value.audits.length > 500 ||
    !value.audits.every(isIndexEntry) ||
    value.audits[0]?.auditId !== value.latestAuditId
  )
    throw new Error('Static report index is invalid.');
  return value as unknown as StaticReportIndex;
}

async function replaceFile(file: string, content: string): Promise<void> {
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, content, { mode: 0o600, flag: 'wx' });
    await rename(temporary, file);
  } finally {
    await rm(temporary, { force: true });
  }
}

async function updateStaticReportIndex(root: string): Promise<StaticReportIndex> {
  const entries = (await readdir(root, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && /^[A-Za-z0-9-]{1,100}$/.test(entry.name))
    .slice(0, 500);
  const audits: StaticReportIndexEntry[] = [];
  for (const entry of entries) {
    const stored = await readStoredIndexEntry(path.join(root, entry.name));
    if (stored) {
      audits.push(stored);
      continue;
    }
    const report = await readIndexedReport(path.join(root, entry.name));
    if (report && report.auditId === entry.name) audits.push(reportIndexEntry(report));
  }
  audits.sort(
    (left, right) =>
      right.generatedAt.localeCompare(left.generatedAt) ||
      right.auditId.localeCompare(left.auditId),
  );
  const latest = audits[0];
  if (!latest) throw new Error('Cannot build an empty static report index.');
  const index: StaticReportIndex = {
    schemaVersion: staticReportIndexVersion,
    kind: 'codebasescan-report-index',
    generatedAt: latest.generatedAt,
    latestAuditId: latest.auditId,
    audits,
  };
  await replaceFile(path.join(root, 'report-index.json'), json(index));
  await replaceFile(path.join(root, 'index.html'), renderStaticReportIndex(index));
  return index;
}

export async function writeStaticReport(
  report: AuditReport,
  outputRoot: string,
  options: StaticReportOptions = {},
): Promise<{
  directory: string;
  rootEntrypoint: string;
  manifest: StaticReportManifest;
  index: StaticReportIndex;
}> {
  const root = path.resolve(outputRoot);
  const directory = path.join(root, safeAuditSegment(report.auditId));
  await mkdir(root, { recursive: true, mode: 0o700 });
  try {
    await mkdir(directory, { mode: 0o700 });
  } catch (cause) {
    if (cause instanceof Error && 'code' in cause && cause.code === 'EEXIST')
      throw new Error(`Report directory already exists: ${directory}`);
    throw cause;
  }

  const plan = parseRemediationPlan(buildRemediationPlan(report));
  const agentReport = parseAgentReport(buildAgentReport(report));
  const agentRules = parseAgentReviewRulePack(agentReviewRulePack);
  const ruleQuality = parseRuleQualityReport(buildRuleQualityReport(report));
  const policyResult = parsePolicyResult(
    options.policyResult ?? buildPolicyResult(report, 'advisory'),
  );
  const remediationResult = options.baseline
    ? parseRemediationResult(
        buildRemediationResult(
          buildRemediationPlan(options.baseline),
          options.baseline,
          report,
          options.verificationLedger,
        ),
      )
    : undefined;
  const artifacts: StaticArtifact[] = [
    {
      path: 'index.html',
      mediaType: 'text/html; charset=utf-8',
      content: toHtml(report, {
        artifactLinks: true,
        remediationPlan: plan,
        remediationResult,
        ruleQuality,
        policyResult,
      }),
    },
    {
      path: 'report-index-entry.json',
      mediaType: 'application/json',
      content: json(reportIndexEntry(report)),
    },
    {
      path: 'audit-report.json',
      mediaType: 'application/json',
      content: json(report),
    },
    ...(report.riskCorrelation
      ? [
          {
            path: 'risk-paths.json',
            mediaType: 'application/json',
            content: json(report.riskCorrelation),
          },
        ]
      : []),
    ...(report.environmentContract
      ? [
          {
            path: 'environment-contract.json',
            mediaType: 'application/json',
            content: json(report.environmentContract),
          },
        ]
      : []),
    ...(report.testEvidence
      ? [
          {
            path: 'test-evidence.json',
            mediaType: 'application/json',
            content: json(report.testEvidence),
          },
        ]
      : []),
    ...(report.apiContract
      ? [
          {
            path: 'api-contract.json',
            mediaType: 'application/json',
            content: json(report.apiContract),
          },
        ]
      : []),
    ...(report.databaseContract
      ? [
          {
            path: 'database-contract.json',
            mediaType: 'application/json',
            content: json(report.databaseContract),
          },
        ]
      : []),
    ...(report.webhookContract
      ? [
          {
            path: 'webhook-contract.json',
            mediaType: 'application/json',
            content: json(report.webhookContract),
          },
        ]
      : []),
    ...(report.featureFlags
      ? [
          {
            path: 'feature-flags.json',
            mediaType: 'application/json',
            content: json(report.featureFlags),
          },
        ]
      : []),
    {
      path: 'agent-plan.json',
      mediaType: 'application/json',
      content: json(plan),
    },
    {
      path: 'agent-report.json',
      mediaType: 'application/json',
      content: json(agentReport),
    },
    {
      path: 'agent-report.schema.json',
      mediaType: 'application/schema+json',
      content: json(agentReportJsonSchema()),
    },
    {
      path: 'agent-rules.json',
      mediaType: 'application/json',
      content: json(agentRules),
    },
    {
      path: 'agent-rules.schema.json',
      mediaType: 'application/schema+json',
      content: json(agentReviewRulePackJsonSchema()),
    },
    {
      path: 'remediation-plan.json',
      mediaType: 'application/json',
      content: json(plan),
    },
    {
      path: 'agent-plan.schema.json',
      mediaType: 'application/schema+json',
      content: json(remediationPlanJsonSchema()),
    },
    {
      path: 'run-manifest.schema.json',
      mediaType: 'application/schema+json',
      content: json(runManifestJsonSchema()),
    },
    {
      path: 'policy-result.json',
      mediaType: 'application/json',
      content: json(policyResult),
    },
    {
      path: 'policy-result.schema.json',
      mediaType: 'application/schema+json',
      content: json(policyResultJsonSchema()),
    },
    {
      path: 'rule-quality.json',
      mediaType: 'application/json',
      content: json(ruleQuality),
    },
    {
      path: 'rule-quality.schema.json',
      mediaType: 'application/schema+json',
      content: json(ruleQualityJsonSchema()),
    },
    {
      path: 'review-ledger.schema.json',
      mediaType: 'application/schema+json',
      content: json(reviewLedgerJsonSchema()),
    },
    {
      path: 'calibration-ledger.schema.json',
      mediaType: 'application/schema+json',
      content: json(calibrationLedgerJsonSchema()),
    },
    {
      path: 'calibration-report.schema.json',
      mediaType: 'application/schema+json',
      content: json(calibrationReportJsonSchema()),
    },
    {
      path: 'suppression-ledger.schema.json',
      mediaType: 'application/schema+json',
      content: json(suppressionLedgerJsonSchema()),
    },
    {
      path: 'verification-ledger.schema.json',
      mediaType: 'application/schema+json',
      content: json(verificationLedgerJsonSchema()),
    },
    {
      path: 'codex-bundle.json',
      mediaType: 'application/json',
      content: json(toInvestigationBundle(report)),
    },
    {
      path: 'report.md',
      mediaType: 'text/markdown; charset=utf-8',
      content: `${toMarkdown(report, { policyResult })}\n`,
    },
    {
      path: 'report.sarif',
      mediaType: 'application/sarif+json',
      content: json(toSarif(report)),
    },
    {
      path: 'sbom.cdx.json',
      mediaType: 'application/vnd.cyclonedx+json',
      content: json(toCycloneDx(report)),
    },
    ...(remediationResult
      ? [
          {
            path: 'remediation-result.schema.json',
            mediaType: 'application/schema+json',
            content: json(remediationResultJsonSchema()),
          },
          {
            path: 'remediation-result.json',
            mediaType: 'application/json',
            content: json(remediationResult),
          },
        ]
      : []),
    ...(options.verificationLedger
      ? [
          {
            path: 'verification-ledger.json',
            mediaType: 'application/json',
            content: json(options.verificationLedger),
          },
        ]
      : []),
  ];
  const runManifest = parseRunManifest(buildRunManifest(report, artifacts.map(describeArtifact)));
  artifacts.splice(2, 0, {
    path: 'run-manifest.json',
    mediaType: 'application/json',
    content: json(runManifest),
  });
  await Promise.all(
    artifacts.map((artifact) =>
      writeFile(path.join(directory, artifact.path), artifact.content, {
        mode: 0o600,
        flag: 'wx',
      }),
    ),
  );
  const manifest: StaticReportManifest = {
    schemaVersion: staticReportVersion,
    kind: 'codebasescan-static-report',
    auditId: report.auditId,
    snapshotDigest: report.snapshotDigest,
    generatedAt: report.createdAt,
    entrypoint: 'index.html',
    files: artifacts.map(describeArtifact),
  };
  await writeFile(path.join(directory, 'manifest.json'), json(manifest), {
    mode: 0o600,
    flag: 'wx',
  });
  const index = await updateStaticReportIndex(root);
  return { directory, rootEntrypoint: path.join(root, 'index.html'), manifest, index };
}
