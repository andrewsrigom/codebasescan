import type { AuditReport, Disposition } from './types.ts';
import { digest } from './findings.ts';
import { redact } from '../security/redact.ts';

export const reviewLedgerVersion = 1 as const;
export type PortableReviewDecision = Extract<
  Disposition,
  'confirmed' | 'false_positive' | 'accepted_risk'
>;

export interface ReviewLedgerEntry {
  fingerprint: string;
  evidenceFileDigests: string[];
  sourceAuditId: string;
  sourceSnapshotDigest: string;
  decision: PortableReviewDecision;
  note: string;
  reviewedAt: string;
}

export interface ReviewLedger {
  schemaVersion: typeof reviewLedgerVersion;
  kind: 'traceward-review-ledger';
  projectName: string;
  updatedAt: string;
  entries: ReviewLedgerEntry[];
}

function evidenceDigests(report: AuditReport, findingId: string): string[] {
  const finding = report.findings.find((candidate) => candidate.id === findingId);
  if (!finding) throw new Error('Finding not found in the source audit report.');
  const digests = [...new Set(finding.evidence.map((evidence) => evidence.fileDigest))].sort();
  if (!digests.length) throw new Error('Finding has no source evidence digest.');
  return digests;
}

export function upsertReviewLedger(
  current: ReviewLedger | undefined,
  report: AuditReport,
  input: {
    findingId: string;
    decision: PortableReviewDecision;
    note: string;
    reviewedAt?: string;
  },
): ReviewLedger {
  if (current && current.projectName !== report.projectName)
    throw new Error('Review ledger belongs to a different project.');
  const finding = report.findings.find((candidate) => candidate.id === input.findingId);
  if (!finding) throw new Error('Finding not found in the source audit report.');
  const note = redact(input.note.trim());
  if (note.length < 12)
    throw new Error('Explain the review decision and evidence in at least 12 characters.');
  const reviewedAt = input.reviewedAt ?? new Date().toISOString();
  if (!Number.isFinite(Date.parse(reviewedAt)))
    throw new Error('Review date must be valid ISO time.');
  const entry: ReviewLedgerEntry = {
    fingerprint: finding.fingerprint,
    evidenceFileDigests: evidenceDigests(report, finding.id),
    sourceAuditId: report.auditId,
    sourceSnapshotDigest: report.snapshotDigest,
    decision: input.decision,
    note,
    reviewedAt: new Date(reviewedAt).toISOString(),
  };
  return {
    schemaVersion: reviewLedgerVersion,
    kind: 'traceward-review-ledger',
    projectName: report.projectName,
    updatedAt: entry.reviewedAt,
    entries: [
      ...(current?.entries.filter((item) => item.fingerprint !== entry.fingerprint) ?? []),
      entry,
    ].sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)),
  };
}

function sameDigests(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function applyReviewLedger(
  report: AuditReport,
  ledger: ReviewLedger,
  importedAt = new Date().toISOString(),
): AuditReport {
  if (ledger.projectName !== report.projectName)
    throw new Error('Review ledger belongs to a different project.');
  const findingsByFingerprint = new Map(
    report.findings.map((finding) => [finding.fingerprint, finding]),
  );
  const applicable = new Map<string, ReviewLedgerEntry>();
  let stale = 0;
  let unmatched = 0;
  for (const entry of ledger.entries) {
    const finding = findingsByFingerprint.get(entry.fingerprint);
    if (!finding) {
      unmatched += 1;
      continue;
    }
    const currentDigests = [
      ...new Set(finding.evidence.map((evidence) => evidence.fileDigest)),
    ].sort();
    if (!sameDigests(currentDigests, entry.evidenceFileDigests)) {
      stale += 1;
      continue;
    }
    applicable.set(entry.fingerprint, entry);
  }
  const sourceAuditIds = [
    ...new Set([...applicable.values()].map((entry) => entry.sourceAuditId)),
  ].sort();
  return {
    ...report,
    schemaVersion: 6,
    findings: report.findings.map((finding) => {
      const entry = applicable.get(finding.fingerprint);
      return entry
        ? {
            ...finding,
            disposition: entry.decision,
            review: {
              decision: entry.decision,
              note: entry.note,
              at: entry.reviewedAt,
            },
          }
        : finding;
    }),
    reviewImport: {
      schemaVersion: 1,
      ledgerDigest: digest(JSON.stringify(ledger)),
      sourceAuditIds,
      importedAt: new Date(importedAt).toISOString(),
      entries: ledger.entries.length,
      applied: applicable.size,
      stale,
      unmatched,
    },
    limitations: [
      ...new Set([
        ...report.limitations,
        'Portable review decisions came from an explicitly supplied ledger. Traceward matched fingerprint and source-file digests but did not authenticate the reviewer.',
      ]),
    ],
  };
}
