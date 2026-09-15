import type { Finding, Severity } from '../domain/types.ts';
import type { LoadedReportPackage } from '../reporting/report-server.ts';
import { compareReports } from '../domain/comparison.ts';

export interface FindingListOptions {
  severity?: Severity;
  rule?: string;
  path?: string;
  limit: number;
}

export function listFindings(reportPackage: LoadedReportPackage, options: FindingListOptions) {
  const matching = reportPackage.report.findings.filter(
    (finding) =>
      (!options.severity || finding.severity === options.severity) &&
      (!options.rule || finding.ruleId === options.rule) &&
      (!options.path || finding.evidence.some((evidence) => evidence.file === options.path)),
  );
  return {
    auditId: reportPackage.report.auditId,
    total: matching.length,
    shown: Math.min(options.limit, matching.length),
    findings: matching.slice(0, options.limit).map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      ruleId: finding.ruleId,
      disposition: finding.disposition,
      location: finding.evidence[0]
        ? `${finding.evidence[0].file}:${finding.evidence[0].focusLine ?? finding.evidence[0].startLine}`
        : null,
    })),
  };
}

export function findFinding(reportPackage: LoadedReportPackage, id: string): Finding {
  const finding = reportPackage.report.findings.find((candidate) => candidate.id === id);
  if (!finding) throw new Error(`Finding not found in verified report: ${id}`);
  return finding;
}

export function showCoverage(reportPackage: LoadedReportPackage, limit: number) {
  const capabilities = reportPackage.report.coverage ?? [];
  const complete = capabilities.filter((item) => item.status === 'COMPLETE').length;
  const incomplete = capabilities.filter((item) => item.status !== 'COMPLETE');
  const ordered = [...incomplete, ...capabilities.filter((item) => item.status === 'COMPLETE')];
  return {
    auditId: reportPackage.report.auditId,
    complete,
    total: capabilities.length,
    incomplete: incomplete.length,
    shown: Math.min(limit, capabilities.length),
    snapshotTruncated: reportPackage.report.truncated,
    capabilities: ordered
      .slice(0, limit)
      .map((item) => ({ id: item.id, status: item.status, detail: item.detail })),
  };
}

export function reportVerification(reportPackage: LoadedReportPackage) {
  return {
    auditId: reportPackage.report.auditId,
    projectName: reportPackage.report.projectName,
    snapshotDigest: reportPackage.report.snapshotDigest,
    artifactsVerified: reportPackage.files.size,
    directory: reportPackage.directory,
  };
}

export function showChanges(
  before: LoadedReportPackage,
  after: LoadedReportPackage,
  limit: number,
) {
  if (before.report.projectName !== after.report.projectName)
    throw new Error('The verified reports belong to different projects.');
  const comparison = compareReports(before.report, after.report);
  const beforeCoverage = new Map(
    (before.report.coverage ?? []).map((item) => [item.id, item.status]),
  );
  const afterCoverage = new Map(
    (after.report.coverage ?? []).map((item) => [item.id, item.status]),
  );
  const coverageChanges = [...new Set([...beforeCoverage.keys(), ...afterCoverage.keys()])]
    .sort()
    .flatMap((id) => {
      const previous = beforeCoverage.get(id) ?? 'NOT REPORTED';
      const current = afterCoverage.get(id) ?? 'NOT REPORTED';
      return previous === current
        ? []
        : [
            {
              id,
              before: previous,
              after: current,
              regression:
                (previous === 'COMPLETE' && current !== 'COMPLETE') ||
                (previous === 'PARTIAL' && current === 'FAILED'),
            },
          ];
    });
  const regressions = coverageChanges.filter((item) => item.regression);
  return {
    beforeAuditId: before.report.auditId,
    afterAuditId: after.report.auditId,
    snapshotChanged: before.report.snapshotDigest !== after.report.snapshotDigest,
    newCount: comparison.newFindings.length,
    resolvedCount: comparison.resolvedFindings.length,
    unchangedCount: comparison.unchangedFindings.length,
    newFindings: comparison.newFindings.slice(0, limit),
    resolvedFindings: comparison.resolvedFindings.slice(0, limit),
    coverageRegressionCount: regressions.length,
    coverageRegressions: regressions.slice(0, limit),
    coverageChanges: coverageChanges.slice(0, limit),
    coverageChangeCount: coverageChanges.length,
    limitation:
      'A finding disappearing from the after report is not proof that the underlying risk was fixed.',
  };
}

export function renderFinding(finding: Finding): string {
  const lines = [
    `${finding.severity.toUpperCase()} ${finding.title}`,
    `ID: ${finding.id}  Rule: ${finding.ruleId}  Status: ${finding.disposition}`,
    `What: ${finding.description}`,
    `Next: ${finding.remediation}`,
    ...finding.evidence.map(
      (evidence) =>
        `Evidence ${evidence.id}: ${evidence.file}:${evidence.focusLine ?? evidence.startLine} (${evidence.kind ?? 'source'}) — ${evidence.observation}`,
    ),
    'Static evidence is a review candidate, not proof of exploitability.',
  ];
  return lines.join('\n');
}
