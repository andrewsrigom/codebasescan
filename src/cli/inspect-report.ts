import type { Finding, Severity } from '../domain/types.ts';
import type { LoadedReportPackage } from '../reporting/report-server.ts';

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

export function showCoverage(reportPackage: LoadedReportPackage) {
  const capabilities = reportPackage.report.coverage ?? [];
  const complete = capabilities.filter((item) => item.status === 'COMPLETE').length;
  const incomplete = capabilities.filter((item) => item.status !== 'COMPLETE');
  return {
    auditId: reportPackage.report.auditId,
    complete,
    total: capabilities.length,
    snapshotTruncated: reportPackage.report.truncated,
    capabilities: [...incomplete, ...capabilities.filter((item) => item.status === 'COMPLETE')].map(
      (item) => ({ id: item.id, status: item.status, detail: item.detail }),
    ),
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
