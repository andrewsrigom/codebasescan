import type { AuditReport, Finding } from './types.ts';
import { digest } from './findings.ts';
import { redact } from '../security/redact.ts';
import { safeRelative } from '../security/paths.ts';

export const suppressionLedgerVersion = 1 as const;

export interface SuppressionLedgerEntry {
  fingerprint: string;
  ruleId: string;
  paths: string[];
  evidenceFileDigests: string[];
  sourceAuditId: string;
  sourceSnapshotDigest: string;
  owner: string;
  justification: string;
  evidence: string;
  createdAt: string;
  expiresAt?: string;
}

export interface SuppressionLedger {
  schemaVersion: typeof suppressionLedgerVersion;
  kind: 'traceward-suppression-ledger';
  projectName: string;
  updatedAt: string;
  entries: SuppressionLedgerEntry[];
}

function sourceTarget(finding: Finding): { paths: string[]; evidenceFileDigests: string[] } {
  const paths = [...new Set(finding.evidence.map((item) => safeRelative(item.file)))].sort();
  const evidenceFileDigests = [...new Set(finding.evidence.map((item) => item.fileDigest))].sort();
  if (!paths.length || !evidenceFileDigests.length)
    throw new Error('Finding has no exact source target for a portable suppression.');
  return { paths, evidenceFileDigests };
}

function normalizedTime(value: string, label: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new Error(`${label} must be valid ISO time.`);
  return new Date(timestamp).toISOString();
}

export function upsertSuppressionLedger(
  current: SuppressionLedger | undefined,
  report: AuditReport,
  input: {
    findingId: string;
    owner: string;
    justification: string;
    evidence: string;
    createdAt?: string;
    expiresAt?: string;
  },
): SuppressionLedger {
  if (current && current.projectName !== report.projectName)
    throw new Error('Suppression ledger belongs to a different project.');
  const finding = report.findings.find((candidate) => candidate.id === input.findingId);
  if (!finding) throw new Error('Finding not found in the source audit report.');

  const owner = redact(input.owner.trim());
  const justification = redact(input.justification.trim());
  const evidence = redact(input.evidence.trim());
  if (owner.length < 2) throw new Error('Name the owner of the suppression.');
  if (justification.length < 12)
    throw new Error('Explain the suppression in at least 12 characters.');
  if (evidence.length < 12)
    throw new Error('Describe the supporting evidence in at least 12 characters.');

  const createdAt = normalizedTime(input.createdAt ?? new Date().toISOString(), 'Creation date');
  const expiresAt = input.expiresAt
    ? normalizedTime(input.expiresAt, 'Suppression expiry')
    : undefined;
  if (expiresAt && Date.parse(expiresAt) <= Date.parse(createdAt))
    throw new Error('Suppression expiry must be after its creation date.');
  const target = sourceTarget(finding);
  const entry: SuppressionLedgerEntry = {
    fingerprint: finding.fingerprint,
    ruleId: finding.ruleId,
    ...target,
    sourceAuditId: report.auditId,
    sourceSnapshotDigest: report.snapshotDigest,
    owner,
    justification,
    evidence,
    createdAt,
    ...(expiresAt ? { expiresAt } : {}),
  };
  return {
    schemaVersion: suppressionLedgerVersion,
    kind: 'traceward-suppression-ledger',
    projectName: report.projectName,
    updatedAt: createdAt,
    entries: [
      ...(current?.entries.filter((item) => item.fingerprint !== entry.fingerprint) ?? []),
      entry,
    ].sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)),
  };
}

function sameValues(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function applySuppressionLedger(
  report: AuditReport,
  ledger: SuppressionLedger,
  importedAt = report.createdAt,
): AuditReport {
  if (ledger.projectName !== report.projectName)
    throw new Error('Suppression ledger belongs to a different project.');
  const findings = new Map(report.findings.map((finding) => [finding.fingerprint, finding]));
  const applicable = new Map<string, SuppressionLedgerEntry>();
  let stale = 0;
  let unmatched = 0;
  let expired = 0;
  for (const entry of ledger.entries) {
    const finding = findings.get(entry.fingerprint);
    if (!finding) {
      unmatched += 1;
      continue;
    }
    const target = sourceTarget(finding);
    if (
      entry.ruleId !== finding.ruleId ||
      !sameValues(entry.paths, target.paths) ||
      !sameValues(entry.evidenceFileDigests, target.evidenceFileDigests)
    ) {
      stale += 1;
      continue;
    }
    if (entry.expiresAt && Date.parse(entry.expiresAt) <= Date.parse(report.createdAt)) {
      expired += 1;
      continue;
    }
    applicable.set(entry.fingerprint, entry);
  }

  const sourceAuditIds = [
    ...new Set([...applicable.values()].map((entry) => entry.sourceAuditId)),
  ].sort();
  return {
    ...report,
    schemaVersion: 14,
    findings: report.findings.map((finding) => {
      const entry = applicable.get(finding.fingerprint);
      return entry
        ? {
            ...finding,
            suppression: {
              reason: entry.justification,
              owner: entry.owner,
              evidence: entry.evidence,
              createdAt: entry.createdAt,
              ...(entry.expiresAt ? { expiresAt: entry.expiresAt } : {}),
              source: 'portable-ledger' as const,
              target: {
                fingerprint: entry.fingerprint,
                ruleId: entry.ruleId,
                paths: entry.paths,
              },
            },
          }
        : finding;
    }),
    suppressionImport: {
      schemaVersion: 1,
      ledgerDigest: digest(JSON.stringify(ledger)),
      sourceAuditIds,
      importedAt: normalizedTime(importedAt, 'Import date'),
      entries: ledger.entries.length,
      applied: applicable.size,
      stale,
      unmatched,
      expired,
    },
    limitations: [
      ...new Set([
        ...report.limitations,
        'Portable suppressions came from an explicitly supplied ledger. Traceward matched fingerprint, rule, paths, and source-file digests but did not authenticate the owner.',
      ]),
    ],
  };
}
