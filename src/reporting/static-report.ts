import path from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import type { AuditReport } from '../domain/types.ts';
import { digest } from '../domain/findings.ts';
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
} from '../domain/remediation-schema.ts';
import { buildRuleQualityReport } from '../domain/rule-quality.ts';
import { parseRuleQualityReport, ruleQualityJsonSchema } from '../domain/rule-quality-schema.ts';
import { reviewLedgerJsonSchema } from '../domain/review-ledger-schema.ts';
import { buildRunManifest, type RunManifestOutput } from '../domain/run-manifest.ts';
import { parseRunManifest, runManifestJsonSchema } from '../domain/run-manifest-schema.ts';
import { buildPolicyResult, type PolicyResult } from '../domain/policy.ts';
import { parsePolicyResult, policyResultJsonSchema } from '../domain/policy-schema.ts';

export const staticReportVersion = 1 as const;

export interface StaticReportManifest {
  schemaVersion: typeof staticReportVersion;
  kind: 'traceward-static-report';
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

export async function writeStaticReport(
  report: AuditReport,
  outputRoot: string,
  options: StaticReportOptions = {},
): Promise<{ directory: string; manifest: StaticReportManifest }> {
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
  const ruleQuality = parseRuleQualityReport(buildRuleQualityReport(report));
  const policyResult = parsePolicyResult(
    options.policyResult ?? buildPolicyResult(report, 'advisory'),
  );
  const remediationResult = options.baseline
    ? parseRemediationResult(
        buildRemediationResult(buildRemediationPlan(options.baseline), options.baseline, report),
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
      }),
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
      path: 'codex-bundle.json',
      mediaType: 'application/json',
      content: json(toInvestigationBundle(report)),
    },
    {
      path: 'report.md',
      mediaType: 'text/markdown; charset=utf-8',
      content: `${toMarkdown(report)}\n`,
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
            path: 'remediation-result.json',
            mediaType: 'application/json',
            content: json(remediationResult),
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
    kind: 'traceward-static-report',
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
  return { directory, manifest };
}
