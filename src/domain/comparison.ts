import type { AuditComparison, AuditReport, Finding, FindingReference } from './types.ts';

function reference(finding: Finding): FindingReference {
  return {
    id: finding.id,
    fingerprint: finding.fingerprint,
    ruleId: finding.ruleId,
    title: finding.title,
    severity: finding.severity,
    ...(finding.suppression ? { suppressed: true } : {}),
  };
}

export function compareReports(base: AuditReport, current: AuditReport): AuditComparison {
  const previous = new Map(base.findings.map((finding) => [finding.fingerprint, finding]));
  const latest = new Map(current.findings.map((finding) => [finding.fingerprint, finding]));
  const newFindings = current.findings.filter((finding) => !previous.has(finding.fingerprint));
  const resolvedFindings = base.findings.filter((finding) => !latest.has(finding.fingerprint));
  const unchangedFindings = current.findings.filter((finding) => previous.has(finding.fingerprint));
  const severityChanges = unchangedFindings.flatMap((finding) => {
    const before = previous.get(finding.fingerprint)?.severity;
    return before && before !== finding.severity
      ? [{ finding: reference(finding), before, after: finding.severity }]
      : [];
  });
  return {
    baseAuditId: base.auditId,
    currentAuditId: current.auditId,
    newFindings: newFindings.map(reference),
    resolvedFindings: resolvedFindings.map(reference),
    unchangedFindings: unchangedFindings.map(reference),
    severityChanges,
  };
}
