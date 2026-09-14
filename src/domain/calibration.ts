import path from 'node:path';
import { redact } from '../security/redact.ts';
import { digest } from './findings.ts';
import type { AuditReport, Finding } from './types.ts';

export const calibrationLedgerVersion = 1 as const;
export const calibrationReportVersion = 2 as const;
export const v1CalibrationGateVersion = 1 as const;

export const calibrationOutcomes = [
  'true_positive',
  'false_positive',
  'not_applicable',
  'inconclusive',
] as const;
export type CalibrationOutcome = (typeof calibrationOutcomes)[number];

export const calibrationRatings = ['correct', 'incorrect', 'uncertain'] as const;
export type CalibrationRating = (typeof calibrationRatings)[number];

export const explanationRatings = ['clear', 'unclear', 'uncertain'] as const;
export type ExplanationRating = (typeof explanationRatings)[number];

export const candidateReviewStates = ['partial', 'complete'] as const;
export type CandidateReviewState = (typeof candidateReviewStates)[number];

export const falseNegativeReviewStates = ['not_performed', 'sampled', 'complete'] as const;
export type FalseNegativeReviewState = (typeof falseNegativeReviewStates)[number];

export interface CalibrationEntry {
  fingerprint: string;
  evidenceFileDigests: string[];
  sourceAuditId: string;
  sourceSnapshotDigest: string;
  source: Finding['source'];
  ruleId: string;
  outcome: CalibrationOutcome;
  evidenceAccuracy: CalibrationRating;
  locationAccuracy: CalibrationRating;
  explanationQuality: ExplanationRating;
  note: string;
  reviewer: string;
  reviewedAt: string;
}

export interface CalibrationMiss {
  id: string;
  sourceAuditId: string;
  sourceSnapshotDigest: string;
  expectedRuleId?: string;
  file: string;
  line?: number;
  note: string;
  reviewer: string;
  reviewedAt: string;
}

export interface CalibrationReviewScope {
  candidateReview: CandidateReviewState;
  falseNegativeReview: FalseNegativeReviewState;
  note: string;
  reviewer: string;
  reviewedAt: string;
}

export interface CalibrationLedger {
  schemaVersion: typeof calibrationLedgerVersion;
  kind: 'codebasescan-calibration-ledger';
  projectName: string;
  sourceAuditId: string;
  sourceSnapshotDigest: string;
  updatedAt: string;
  reviewScope?: CalibrationReviewScope;
  entries: CalibrationEntry[];
  manualMisses: CalibrationMiss[];
}

type OutcomeCounts = Record<CalibrationOutcome, number>;
type RatingCounts = Record<CalibrationRating, number>;
type ExplanationCounts = Record<ExplanationRating, number>;

export interface CalibrationReport {
  schemaVersion: typeof calibrationReportVersion;
  kind: 'codebasescan-calibration-report';
  generatedAt: string;
  summary: {
    reports: number;
    projects: number;
    findings: number;
    reviewedCandidates: number;
    unreviewedCandidates: number;
    manualMisses: number;
    outcomes: OutcomeCounts;
    evidenceAccuracy: RatingCounts;
    locationAccuracy: RatingCounts;
    explanationQuality: ExplanationCounts;
    criticalHighReviewedCandidates: number;
    criticalHighOutcomes: OutcomeCounts;
    samplePrecision?: number;
    criticalHighSamplePrecision?: number;
    reviewedRecall?: number;
    candidateReviewComplete: boolean;
    falseNegativeReviewComplete: boolean;
    accuracyClaimReady: boolean;
  };
  projects: {
    label: string;
    filesAnalyzed: number;
    truncated: boolean;
    findings: number;
    reviewedCandidates: number;
    manualMisses: number;
    candidateReview: CandidateReviewState | 'not_recorded';
    falseNegativeReview: FalseNegativeReviewState;
    coverage: Record<string, number>;
  }[];
  rules: {
    id: string;
    source: Finding['source'] | 'manual';
    ruleId: string;
    projectsObserved: number;
    candidates: number;
    reviewedCandidates: number;
    manualMisses: number;
    outcomes: OutcomeCounts;
    evidenceAccuracy: RatingCounts;
    locationAccuracy: RatingCounts;
    explanationQuality: ExplanationCounts;
  }[];
  limitations: string[];
}

export type CalibrationGateCheckStatus = 'pass' | 'fail' | 'incomplete';

export interface V1CalibrationGate {
  schemaVersion: typeof v1CalibrationGateVersion;
  kind: 'codebasescan-v1-calibration-gate';
  generatedAt: string;
  status: CalibrationGateCheckStatus;
  checks: {
    id: string;
    status: CalibrationGateCheckStatus;
    actual: number | boolean | null;
    required: string;
    detail: string;
  }[];
  limitations: string[];
  calibration: CalibrationReport;
}

function isoTime(value = new Date().toISOString()): string {
  if (!Number.isFinite(Date.parse(value))) throw new Error('Review date must be valid ISO time.');
  return new Date(value).toISOString();
}

function reviewedText(value: string, label: string, minimum = 2): string {
  const result = redact(value.trim());
  if (result.length < minimum) throw new Error(`${label} is too short.`);
  return result;
}

function evidenceDigests(finding: Finding): string[] {
  const values = [...new Set(finding.evidence.map((evidence) => evidence.fileDigest))].sort();
  if (!values.length) throw new Error('Finding has no source evidence digest.');
  return values;
}

function baseLedger(report: AuditReport, updatedAt: string): CalibrationLedger {
  return {
    schemaVersion: calibrationLedgerVersion,
    kind: 'codebasescan-calibration-ledger',
    projectName: report.projectName,
    sourceAuditId: report.auditId,
    sourceSnapshotDigest: report.snapshotDigest,
    updatedAt,
    entries: [],
    manualMisses: [],
  };
}

function assertLedgerMatches(report: AuditReport, ledger: CalibrationLedger): void {
  if (
    ledger.projectName !== report.projectName ||
    ledger.sourceAuditId !== report.auditId ||
    ledger.sourceSnapshotDigest !== report.snapshotDigest
  )
    throw new Error('Calibration ledger belongs to a different audit snapshot.');
}

function currentLedger(
  current: CalibrationLedger | undefined,
  report: AuditReport,
  updatedAt: string,
): CalibrationLedger {
  if (current) assertLedgerMatches(report, current);
  return current ?? baseLedger(report, updatedAt);
}

export function upsertCalibrationEntry(
  current: CalibrationLedger | undefined,
  report: AuditReport,
  input: {
    findingId: string;
    outcome: CalibrationOutcome;
    evidenceAccuracy: CalibrationRating;
    locationAccuracy: CalibrationRating;
    explanationQuality: ExplanationRating;
    note: string;
    reviewer: string;
    reviewedAt?: string;
  },
): CalibrationLedger {
  const finding = report.findings.find((candidate) => candidate.id === input.findingId);
  if (!finding) throw new Error('Finding not found in the source audit report.');
  const reviewedAt = isoTime(input.reviewedAt);
  const ledger = currentLedger(current, report, reviewedAt);
  const entry: CalibrationEntry = {
    fingerprint: finding.fingerprint,
    evidenceFileDigests: evidenceDigests(finding),
    sourceAuditId: report.auditId,
    sourceSnapshotDigest: report.snapshotDigest,
    source: finding.source,
    ruleId: finding.ruleId,
    outcome: input.outcome,
    evidenceAccuracy: input.evidenceAccuracy,
    locationAccuracy: input.locationAccuracy,
    explanationQuality: input.explanationQuality,
    note: reviewedText(input.note, 'Calibration note', 12),
    reviewer: reviewedText(input.reviewer, 'Reviewer'),
    reviewedAt,
  };
  return {
    ...ledger,
    updatedAt: reviewedAt,
    entries: [
      ...ledger.entries.filter((item) => item.fingerprint !== finding.fingerprint),
      entry,
    ].sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)),
  };
}

function relativeSourcePath(value: string): string {
  const normalized = value.replaceAll('\\', '/');
  if (path.posix.isAbsolute(normalized)) throw new Error('Manual miss file must be relative.');
  const resolved = path.posix.normalize(normalized);
  if (!resolved || resolved === '.' || resolved === '..' || resolved.startsWith('../'))
    throw new Error('Manual miss file must stay inside the audited project.');
  return resolved;
}

export function addCalibrationMiss(
  current: CalibrationLedger | undefined,
  report: AuditReport,
  input: {
    file: string;
    line?: number;
    expectedRuleId?: string;
    note: string;
    reviewer: string;
    reviewedAt?: string;
  },
): CalibrationLedger {
  const reviewedAt = isoTime(input.reviewedAt);
  const ledger = currentLedger(current, report, reviewedAt);
  const file = relativeSourcePath(input.file);
  if (input.line !== undefined && (!Number.isInteger(input.line) || input.line < 1))
    throw new Error('Manual miss line must be a positive integer.');
  const note = reviewedText(input.note, 'Manual miss note', 12);
  const reviewer = reviewedText(input.reviewer, 'Reviewer');
  const expectedRuleId = input.expectedRuleId?.trim();
  const id = digest(
    [report.snapshotDigest, expectedRuleId ?? '', file, input.line ?? '', note].join('\0'),
  ).slice(0, 20);
  const miss: CalibrationMiss = {
    id,
    sourceAuditId: report.auditId,
    sourceSnapshotDigest: report.snapshotDigest,
    ...(expectedRuleId ? { expectedRuleId: redact(expectedRuleId) } : {}),
    file,
    ...(input.line ? { line: input.line } : {}),
    note,
    reviewer,
    reviewedAt,
  };
  return {
    ...ledger,
    updatedAt: reviewedAt,
    manualMisses: [...ledger.manualMisses.filter((item) => item.id !== id), miss].sort((a, b) =>
      a.id.localeCompare(b.id),
    ),
  };
}

export function updateCalibrationScope(
  current: CalibrationLedger | undefined,
  report: AuditReport,
  input: {
    candidateReview: CandidateReviewState;
    falseNegativeReview: FalseNegativeReviewState;
    note: string;
    reviewer: string;
    reviewedAt?: string;
  },
): CalibrationLedger {
  const reviewedAt = isoTime(input.reviewedAt);
  const ledger = currentLedger(current, report, reviewedAt);
  return {
    ...ledger,
    updatedAt: reviewedAt,
    reviewScope: {
      candidateReview: input.candidateReview,
      falseNegativeReview: input.falseNegativeReview,
      note: reviewedText(input.note, 'Review scope note', 12),
      reviewer: reviewedText(input.reviewer, 'Reviewer'),
      reviewedAt,
    },
  };
}

function emptyOutcomes(): OutcomeCounts {
  return { true_positive: 0, false_positive: 0, not_applicable: 0, inconclusive: 0 };
}

function emptyRatings(): RatingCounts {
  return { correct: 0, incorrect: 0, uncertain: 0 };
}

function emptyExplanationRatings(): ExplanationCounts {
  return { clear: 0, unclear: 0, uncertain: 0 };
}

function coverageCounts(report: AuditReport): Record<string, number> {
  const result: Record<string, number> = {};
  for (const capability of report.coverage ?? [])
    result[capability.status] = (result[capability.status] ?? 0) + 1;
  return result;
}

export function buildCalibrationReport(
  inputs: { report: AuditReport; ledger?: CalibrationLedger }[],
  generatedAt = new Date().toISOString(),
): CalibrationReport {
  if (!inputs.length) throw new Error('At least one audit report is required for calibration.');
  const projectNames = new Set(inputs.map(({ report }) => report.projectName));
  if (projectNames.size !== inputs.length)
    throw new Error('Calibration requires one audit snapshot per project.');
  for (const { report, ledger } of inputs) if (ledger) assertLedgerMatches(report, ledger);

  const outcomes = emptyOutcomes();
  const evidenceAccuracy = emptyRatings();
  const locationAccuracy = emptyRatings();
  const explanationQuality = emptyExplanationRatings();
  const criticalHighOutcomes = emptyOutcomes();
  const ruleGroups = new Map<
    string,
    {
      source: Finding['source'] | 'manual';
      ruleId: string;
      projects: Set<number>;
      candidates: number;
      entries: CalibrationEntry[];
      manualMisses: number;
    }
  >();
  let reviewedCandidates = 0;
  let criticalHighReviewedCandidates = 0;
  let manualMisses = 0;

  const projects = inputs.map(({ report, ledger }, index) => {
    const entries = ledger?.entries ?? [];
    const byFingerprint = new Map(report.findings.map((finding) => [finding.fingerprint, finding]));
    for (const entry of entries) {
      const finding = byFingerprint.get(entry.fingerprint);
      if (
        !finding ||
        JSON.stringify(evidenceDigests(finding)) !== JSON.stringify(entry.evidenceFileDigests)
      )
        throw new Error('Calibration entry does not match current finding evidence.');
      outcomes[entry.outcome]++;
      evidenceAccuracy[entry.evidenceAccuracy]++;
      locationAccuracy[entry.locationAccuracy]++;
      explanationQuality[entry.explanationQuality]++;
      reviewedCandidates++;
      if (finding.severity === 'critical' || finding.severity === 'high') {
        criticalHighOutcomes[entry.outcome]++;
        criticalHighReviewedCandidates++;
      }
    }
    for (const finding of report.findings) {
      const id = `${finding.source}:${finding.ruleId}`;
      const group = ruleGroups.get(id) ?? {
        source: finding.source,
        ruleId: finding.ruleId,
        projects: new Set<number>(),
        candidates: 0,
        entries: [],
        manualMisses: 0,
      };
      group.projects.add(index);
      group.candidates++;
      const entry = entries.find((item) => item.fingerprint === finding.fingerprint);
      if (entry) group.entries.push(entry);
      ruleGroups.set(id, group);
    }
    for (const miss of ledger?.manualMisses ?? []) {
      manualMisses++;
      const ruleId = miss.expectedRuleId ?? 'unassigned';
      const id = `manual:${ruleId}`;
      const group = ruleGroups.get(id) ?? {
        source: 'manual' as const,
        ruleId,
        projects: new Set<number>(),
        candidates: 0,
        entries: [],
        manualMisses: 0,
      };
      group.projects.add(index);
      group.manualMisses++;
      ruleGroups.set(id, group);
    }
    return {
      label: `P${String(index + 1).padStart(2, '0')}`,
      filesAnalyzed: report.filesAnalyzed,
      truncated: report.truncated,
      findings: report.findings.length,
      reviewedCandidates: entries.length,
      manualMisses: ledger?.manualMisses.length ?? 0,
      candidateReview: ledger?.reviewScope?.candidateReview ?? ('not_recorded' as const),
      falseNegativeReview: ledger?.reviewScope?.falseNegativeReview ?? ('not_performed' as const),
      coverage: coverageCounts(report),
    };
  });

  const findings = inputs.reduce((sum, { report }) => sum + report.findings.length, 0);
  const candidateReviewComplete = inputs.every(
    ({ report, ledger }) =>
      ledger?.reviewScope?.candidateReview === 'complete' &&
      ledger.entries.length === report.findings.length,
  );
  const falseNegativeReviewComplete = inputs.every(
    ({ ledger }) => ledger?.reviewScope?.falseNegativeReview === 'complete',
  );
  const decided = outcomes.true_positive + outcomes.false_positive;
  const criticalHighDecided =
    criticalHighOutcomes.true_positive + criticalHighOutcomes.false_positive;
  const recallDenominator = outcomes.true_positive + manualMisses;
  const accuracyClaimReady =
    candidateReviewComplete && falseNegativeReviewComplete && outcomes.inconclusive === 0;

  return {
    schemaVersion: calibrationReportVersion,
    kind: 'codebasescan-calibration-report',
    generatedAt: isoTime(generatedAt),
    summary: {
      reports: inputs.length,
      projects: projectNames.size,
      findings,
      reviewedCandidates,
      unreviewedCandidates: findings - reviewedCandidates,
      manualMisses,
      outcomes,
      evidenceAccuracy,
      locationAccuracy,
      explanationQuality,
      criticalHighReviewedCandidates,
      criticalHighOutcomes,
      ...(decided ? { samplePrecision: outcomes.true_positive / decided } : {}),
      ...(criticalHighDecided
        ? {
            criticalHighSamplePrecision: criticalHighOutcomes.true_positive / criticalHighDecided,
          }
        : {}),
      ...(falseNegativeReviewComplete && recallDenominator
        ? { reviewedRecall: outcomes.true_positive / recallDenominator }
        : {}),
      candidateReviewComplete,
      falseNegativeReviewComplete,
      accuracyClaimReady,
    },
    projects,
    rules: [...ruleGroups.entries()]
      .map(([id, group]) => {
        const ruleOutcomes = emptyOutcomes();
        const ruleEvidence = emptyRatings();
        const ruleLocation = emptyRatings();
        const ruleExplanation = emptyExplanationRatings();
        for (const entry of group.entries) {
          ruleOutcomes[entry.outcome]++;
          ruleEvidence[entry.evidenceAccuracy]++;
          ruleLocation[entry.locationAccuracy]++;
          ruleExplanation[entry.explanationQuality]++;
        }
        return {
          id,
          source: group.source,
          ruleId: group.ruleId,
          projectsObserved: group.projects.size,
          candidates: group.candidates,
          reviewedCandidates: group.entries.length,
          manualMisses: group.manualMisses,
          outcomes: ruleOutcomes,
          evidenceAccuracy: ruleEvidence,
          locationAccuracy: ruleLocation,
          explanationQuality: ruleExplanation,
        };
      })
      .sort((left, right) => left.id.localeCompare(right.id)),
    limitations: [
      'Candidate outcomes are independent reviewer labels; scanner output alone is not ground truth.',
      'Sample precision is descriptive and is not a general accuracy claim.',
      'Recall is omitted unless every project records a complete false-negative review.',
      'Project labels are anonymized and raw source is not included.',
    ],
  };
}

function thresholdCheck(
  id: string,
  actual: number | undefined,
  minimum: number,
  detail: string,
): V1CalibrationGate['checks'][number] {
  return {
    id,
    status: actual === undefined ? 'incomplete' : actual >= minimum ? 'pass' : 'fail',
    actual: actual ?? null,
    required: `>= ${minimum}`,
    detail,
  };
}

function ratio(numerator: number, denominator: number): number | undefined {
  return denominator > 0 ? numerator / denominator : undefined;
}

export function buildV1CalibrationGate(calibration: CalibrationReport): V1CalibrationGate {
  const boundedFalseNegativeReviews = calibration.projects.filter(
    (project) => project.falseNegativeReview !== 'not_performed',
  ).length;
  const completeFalseNegativeReviews = calibration.projects.filter(
    (project) => project.falseNegativeReview === 'complete',
  ).length;
  const checks: V1CalibrationGate['checks'] = [
    thresholdCheck(
      'repositories',
      calibration.summary.projects,
      10,
      'Structurally different authorized repositories in the aggregate.',
    ),
    thresholdCheck(
      'reviewed-candidates',
      calibration.summary.reviewedCandidates,
      200,
      'Candidates with source-backed reviewer labels.',
    ),
    thresholdCheck(
      'sample-precision',
      calibration.summary.samplePrecision,
      0.85,
      'True positives divided by decided true and false positives.',
    ),
    thresholdCheck(
      'critical-high-sample-precision',
      calibration.summary.criticalHighSamplePrecision,
      0.9,
      'Critical and high true positives divided by decided critical and high candidates.',
    ),
    thresholdCheck(
      'evidence-accuracy',
      ratio(calibration.summary.evidenceAccuracy.correct, calibration.summary.reviewedCandidates),
      0.95,
      'Reviewed candidates rated with correct evidence.',
    ),
    thresholdCheck(
      'location-accuracy',
      ratio(calibration.summary.locationAccuracy.correct, calibration.summary.reviewedCandidates),
      0.95,
      'Reviewed candidates rated with correct source locations.',
    ),
    {
      id: 'bounded-false-negative-review',
      status: boundedFalseNegativeReviews === calibration.summary.projects ? 'pass' : 'fail',
      actual: boundedFalseNegativeReviews,
      required: `= ${calibration.summary.projects}`,
      detail: 'Repositories with at least a sampled false-negative review.',
    },
    thresholdCheck(
      'complete-source-checklist-review',
      completeFalseNegativeReviews,
      3,
      'Repositories with a complete review of the declared source-only checklist.',
    ),
  ];
  const status: CalibrationGateCheckStatus = checks.some((check) => check.status === 'fail')
    ? 'fail'
    : checks.some((check) => check.status === 'incomplete')
      ? 'incomplete'
      : 'pass';
  return {
    schemaVersion: v1CalibrationGateVersion,
    kind: 'codebasescan-v1-calibration-gate',
    generatedAt: calibration.generatedAt,
    status,
    checks,
    limitations: [
      'This gate evaluates the real-project calibration subset of the v1 acceptance contract only.',
      'Duplicate review, regression coverage, report, safety, portability, performance, and release-integrity evidence are evaluated by separate v1 gates.',
      ...calibration.limitations,
    ],
    calibration,
  };
}
