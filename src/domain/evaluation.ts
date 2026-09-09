import type { AuditReport, Finding, SecurityControlReviewDecision } from './types.ts';

export interface EvaluationSummary {
  schemaVersion: 1;
  reports: number;
  filesAnalyzed: number;
  truncatedReports: number;
  findings: number;
  reviewedFindings: number;
  confirmedFindings: number;
  fixedFindings: number;
  falsePositives: number;
  acceptedRisks: number;
  unresolvedFindings: number;
  modelInvestigations: number;
  modelInconclusive: number;
  reviewedControls: number;
  controlReviews: Record<SecurityControlReviewDecision, number>;
  approximateAiCostUsd?: number;
  approximateAiCostPerConfirmedFindingUsd?: number;
  internalCandidates: number;
  externalScannerCandidates: number;
  ruleOutcomes: {
    ruleId: string;
    candidates: number;
    confirmed: number;
    fixed: number;
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
  const controls = reports.flatMap((report) => report.checklist?.controls ?? []);
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
  const controlReviews: Record<SecurityControlReviewDecision, number> = {
    verified_external: 0,
    accepted_gap: 0,
    not_applicable: 0,
    needs_follow_up: 0,
  };
  for (const control of controls) if (control.review) controlReviews[control.review.decision]++;
  return {
    schemaVersion: 1,
    reports: reports.length,
    filesAnalyzed: reports.reduce((sum, report) => sum + report.filesAnalyzed, 0),
    truncatedReports: reports.filter((report) => report.truncated).length,
    findings: findings.length,
    reviewedFindings: findings.filter((finding) => finding.review).length,
    confirmedFindings,
    fixedFindings: countDisposition(findings, 'fixed'),
    falsePositives: countDisposition(findings, 'false_positive'),
    acceptedRisks: countDisposition(findings, 'accepted_risk'),
    unresolvedFindings: countDisposition(findings, 'needs_review'),
    modelInvestigations: findings.filter((finding) => finding.analysis?.provider).length,
    modelInconclusive: findings.filter(
      (finding) => finding.analysis?.provider && finding.analysis.assessment === 'inconclusive',
    ).length,
    reviewedControls: Object.values(controlReviews).reduce((sum, count) => sum + count, 0),
    controlReviews,
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
        fixed: countDisposition(candidates, 'fixed'),
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
