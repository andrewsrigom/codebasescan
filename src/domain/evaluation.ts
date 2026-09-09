import type { AuditReport, Finding } from './types.ts';

export interface EvaluationSummary {
  schemaVersion: 1;
  reports: number;
  filesAnalyzed: number;
  truncatedReports: number;
  findings: number;
  reviewedFindings: number;
  confirmedFindings: number;
  falsePositives: number;
  acceptedRisks: number;
  unresolvedFindings: number;
  modelInvestigations: number;
  modelInconclusive: number;
  approximateAiCostUsd?: number;
  approximateAiCostPerConfirmedFindingUsd?: number;
  internalCandidates: number;
  externalScannerCandidates: number;
  ruleOutcomes: {
    ruleId: string;
    candidates: number;
    confirmed: number;
    falsePositives: number;
    acceptedRisks: number;
    unresolved: number;
  }[];
  coverage: Record<string, number>;
  warning: string;
}

function countDisposition(findings: Finding[], disposition: Finding['disposition']): number {
  return findings.filter((finding) => finding.disposition === disposition).length;
}

export function evaluateReports(reports: AuditReport[]): EvaluationSummary {
  if (!reports.length) throw new Error('At least one audit report is required for evaluation.');
  const findings = reports.flatMap((report) => report.findings);
  const confirmedFindings = countDisposition(findings, 'confirmed');
  const approximateAiCostUsd = reports.reduce(
    (sum, report) => sum + (report.aiUsage?.approximateCostUsd ?? 0),
    0,
  );
  const ruleIds = [...new Set(findings.map((finding) => finding.ruleId))].sort();
  const coverage: Record<string, number> = {};
  for (const report of reports)
    for (const capability of report.coverage ?? [])
      coverage[`${capability.id}:${capability.status}`] =
        (coverage[`${capability.id}:${capability.status}`] ?? 0) + 1;
  const externalSources = new Set<FindingsSource>(['semgrep', 'gitleaks', 'osv']);
  return {
    schemaVersion: 1,
    reports: reports.length,
    filesAnalyzed: reports.reduce((sum, report) => sum + report.filesAnalyzed, 0),
    truncatedReports: reports.filter((report) => report.truncated).length,
    findings: findings.length,
    reviewedFindings: findings.filter((finding) => finding.review).length,
    confirmedFindings,
    falsePositives: countDisposition(findings, 'false_positive'),
    acceptedRisks: countDisposition(findings, 'accepted_risk'),
    unresolvedFindings: countDisposition(findings, 'needs_review'),
    modelInvestigations: findings.filter((finding) => finding.analysis?.provider).length,
    modelInconclusive: findings.filter(
      (finding) => finding.analysis?.provider && finding.analysis.assessment === 'inconclusive',
    ).length,
    ...(approximateAiCostUsd > 0 ? { approximateAiCostUsd } : {}),
    ...(approximateAiCostUsd > 0 && confirmedFindings > 0
      ? { approximateAiCostPerConfirmedFindingUsd: approximateAiCostUsd / confirmedFindings }
      : {}),
    internalCandidates: findings.filter(
      (finding) => !externalSources.has(finding.source as FindingsSource),
    ).length,
    externalScannerCandidates: findings.filter((finding) =>
      externalSources.has(finding.source as FindingsSource),
    ).length,
    ruleOutcomes: ruleIds.map((ruleId) => {
      const candidates = findings.filter((finding) => finding.ruleId === ruleId);
      return {
        ruleId,
        candidates: candidates.length,
        confirmed: countDisposition(candidates, 'confirmed'),
        falsePositives: countDisposition(candidates, 'false_positive'),
        acceptedRisks: countDisposition(candidates, 'accepted_risk'),
        unresolved: countDisposition(candidates, 'needs_review'),
      };
    }),
    coverage,
    warning:
      'Aggregates human dispositions and recorded coverage only. It does not measure undiscovered false negatives or establish generic accuracy.',
  };
}

type FindingsSource = Finding['source'];
