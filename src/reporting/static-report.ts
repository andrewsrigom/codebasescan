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
}

const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

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
  const remediationResult = options.baseline
    ? parseRemediationResult(
        buildRemediationResult(buildRemediationPlan(options.baseline), options.baseline, report),
      )
    : undefined;
  const artifacts = [
    {
      path: 'index.html',
      mediaType: 'text/html; charset=utf-8',
      content: toHtml(report, { artifactLinks: true, remediationPlan: plan, remediationResult }),
    },
    {
      path: 'audit-report.json',
      mediaType: 'application/json',
      content: json(report),
    },
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
    files: artifacts.map((artifact) => ({
      path: artifact.path,
      mediaType: artifact.mediaType,
      bytes: Buffer.byteLength(artifact.content),
      sha256: digest(artifact.content),
    })),
  };
  await writeFile(path.join(directory, 'manifest.json'), json(manifest), {
    mode: 0o600,
    flag: 'wx',
  });
  return { directory, manifest };
}
