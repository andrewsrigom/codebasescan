import type { AuditComparison, AuditReport, Severity } from './types.ts';
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
      !['fixed', 'false_positive', 'accepted_risk'].includes(finding.disposition) &&
      !finding.suppression &&
      severityRank(finding.severity) <= threshold,
  ).length;
  return { exitCode: gatedFindings ? 1 : 0, gatedFindings };
}

export function baselineCiGate(
  comparison: AuditComparison,
  failOn?: Severity,
): { exitCode: 0 | 1; gatedFindings: number } {
  if (!failOn) return { exitCode: 0, gatedFindings: 0 };
  const threshold = severityRank(failOn);
  const gatedFindings = comparison.newFindings.filter(
    (finding) => !finding.suppressed && severityRank(finding.severity) <= threshold,
  ).length;
  return { exitCode: gatedFindings ? 1 : 0, gatedFindings };
}
