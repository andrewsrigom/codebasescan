import { z } from 'zod';
import type { CalibrationLedger, CalibrationReport, V1CalibrationGate } from './calibration.ts';

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const shortText = z.string().min(1).max(10_000);
const outcome = z.enum(['true_positive', 'false_positive', 'not_applicable', 'inconclusive']);
const rating = z.enum(['correct', 'incorrect', 'uncertain']);
const explanation = z.enum(['clear', 'unclear', 'uncertain']);
const source = z.enum([
  'builtin',
  'posture',
  'ast',
  'saas',
  'next',
  'react',
  'accessibility',
  'axe',
  'web',
  'privacy',
  'reliability',
  'environment',
  'supply-chain',
  'http-probe',
  'osv',
  'semgrep',
  'gitleaks',
]);
const outcomeCounts = z.object({
  true_positive: z.number().int().nonnegative(),
  false_positive: z.number().int().nonnegative(),
  not_applicable: z.number().int().nonnegative(),
  inconclusive: z.number().int().nonnegative(),
});
const ratingCounts = z.object({
  correct: z.number().int().nonnegative(),
  incorrect: z.number().int().nonnegative(),
  uncertain: z.number().int().nonnegative(),
});
const explanationCounts = z.object({
  clear: z.number().int().nonnegative(),
  unclear: z.number().int().nonnegative(),
  uncertain: z.number().int().nonnegative(),
});

const ledgerSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal('codebasescan-calibration-ledger'),
  projectName: shortText,
  sourceAuditId: shortText,
  sourceSnapshotDigest: digest,
  updatedAt: z.iso.datetime(),
  reviewScope: z
    .object({
      candidateReview: z.enum(['partial', 'complete']),
      falseNegativeReview: z.enum(['not_performed', 'sampled', 'complete']),
      note: z.string().min(12).max(10_000),
      reviewer: shortText,
      reviewedAt: z.iso.datetime(),
    })
    .optional(),
  entries: z
    .array(
      z.object({
        fingerprint: digest,
        evidenceFileDigests: z.array(digest).min(1).max(100),
        sourceAuditId: shortText,
        sourceSnapshotDigest: digest,
        source,
        ruleId: shortText,
        outcome,
        evidenceAccuracy: rating,
        locationAccuracy: rating,
        explanationQuality: explanation,
        note: z.string().min(12).max(10_000),
        reviewer: shortText,
        reviewedAt: z.iso.datetime(),
      }),
    )
    .max(10_000),
  manualMisses: z
    .array(
      z.object({
        id: z.string().regex(/^[a-f0-9]{20}$/),
        sourceAuditId: shortText,
        sourceSnapshotDigest: digest,
        expectedRuleId: shortText.optional(),
        file: shortText,
        line: z.number().int().positive().optional(),
        note: z.string().min(12).max(10_000),
        reviewer: shortText,
        reviewedAt: z.iso.datetime(),
      }),
    )
    .max(10_000),
});

const reportSchema = z.object({
  schemaVersion: z.literal(2),
  kind: z.literal('codebasescan-calibration-report'),
  generatedAt: z.iso.datetime(),
  summary: z.object({
    reports: z.number().int().positive(),
    projects: z.number().int().positive(),
    findings: z.number().int().nonnegative(),
    reviewedCandidates: z.number().int().nonnegative(),
    unreviewedCandidates: z.number().int().nonnegative(),
    manualMisses: z.number().int().nonnegative(),
    outcomes: outcomeCounts,
    evidenceAccuracy: ratingCounts,
    locationAccuracy: ratingCounts,
    explanationQuality: explanationCounts,
    criticalHighReviewedCandidates: z.number().int().nonnegative(),
    criticalHighOutcomes: outcomeCounts,
    samplePrecision: z.number().min(0).max(1).optional(),
    criticalHighSamplePrecision: z.number().min(0).max(1).optional(),
    reviewedRecall: z.number().min(0).max(1).optional(),
    candidateReviewComplete: z.boolean(),
    falseNegativeReviewComplete: z.boolean(),
    accuracyClaimReady: z.boolean(),
  }),
  projects: z
    .array(
      z.object({
        label: z.string().regex(/^P\d{2}$/),
        filesAnalyzed: z.number().int().nonnegative(),
        truncated: z.boolean(),
        findings: z.number().int().nonnegative(),
        reviewedCandidates: z.number().int().nonnegative(),
        manualMisses: z.number().int().nonnegative(),
        candidateReview: z.enum(['not_recorded', 'partial', 'complete']),
        falseNegativeReview: z.enum(['not_performed', 'sampled', 'complete']),
        coverage: z.record(z.string(), z.number().int().nonnegative()),
      }),
    )
    .max(1_000),
  rules: z
    .array(
      z.object({
        id: shortText,
        source: z.union([source, z.literal('manual')]),
        ruleId: shortText,
        projectsObserved: z.number().int().nonnegative(),
        candidates: z.number().int().nonnegative(),
        reviewedCandidates: z.number().int().nonnegative(),
        manualMisses: z.number().int().nonnegative(),
        outcomes: outcomeCounts,
        evidenceAccuracy: ratingCounts,
        locationAccuracy: ratingCounts,
        explanationQuality: explanationCounts,
      }),
    )
    .max(20_000),
  limitations: z.array(shortText).max(100),
});

const gateCheckStatus = z.enum(['pass', 'fail', 'incomplete']);
const v1CalibrationGateSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal('codebasescan-v1-calibration-gate'),
  generatedAt: z.iso.datetime(),
  status: gateCheckStatus,
  checks: z
    .array(
      z.object({
        id: shortText,
        status: gateCheckStatus,
        actual: z.union([z.number(), z.boolean(), z.null()]),
        required: shortText,
        detail: shortText,
      }),
    )
    .min(1)
    .max(100),
  limitations: z.array(shortText).max(100),
  calibration: reportSchema,
});

export function parseCalibrationLedger(value: unknown): CalibrationLedger {
  return ledgerSchema.parse(value) as CalibrationLedger;
}

export function calibrationLedgerJsonSchema(): unknown {
  return z.toJSONSchema(ledgerSchema, { target: 'draft-07', unrepresentable: 'throw' });
}

export function parseCalibrationReport(value: unknown): CalibrationReport {
  return reportSchema.parse(value) as CalibrationReport;
}

export function calibrationReportJsonSchema(): unknown {
  return z.toJSONSchema(reportSchema, { target: 'draft-07', unrepresentable: 'throw' });
}

export function parseV1CalibrationGate(value: unknown): V1CalibrationGate {
  return v1CalibrationGateSchema.parse(value) as V1CalibrationGate;
}

export function v1CalibrationGateJsonSchema(): unknown {
  return z.toJSONSchema(v1CalibrationGateSchema, {
    target: 'draft-07',
    unrepresentable: 'throw',
  });
}
