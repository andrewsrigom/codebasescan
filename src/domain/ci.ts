import type { AuditReport, Severity } from './types.ts';
import { severityRank } from './findings.ts';

export function ciGate(
  report: AuditReport,
  failOn?: Severity,
): {
  exitCode: 0 | 1;
  gatedFindings: number;
} {
  if (!failOn) return { exitCode: 0, gatedFindings: 0 };
  const threshold = severityRank(failOn);
  const gatedFindings = report.findings.filter(
    (finding) =>
      !['false_positive', 'accepted_risk'].includes(finding.disposition) &&
      severityRank(finding.severity) <= threshold,
  ).length;
  return { exitCode: gatedFindings ? 1 : 0, gatedFindings };
}
