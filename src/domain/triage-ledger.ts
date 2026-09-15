import type { AuditReport, Finding } from './types.ts';
import { redact } from '../security/redact.ts';

export const triageLedgerVersion = 1 as const;
export const triageAssessments = ['likely_valid', 'likely_false_positive', 'inconclusive'] as const;
export type TriageAssessment = (typeof triageAssessments)[number];

export interface TriageEntry {
  fingerprint: string;
  ruleId: string;
  evidenceFileDigests: string[];
  evidenceIds: string[];
  sourceAuditId: string;
  sourceSnapshotDigest: string;
  assessment: TriageAssessment;
  note: string;
  assessedAt: string;
  origin: 'external-agent';
}

export interface TriageLedger {
  schemaVersion: typeof triageLedgerVersion;
  kind: 'codebasescan-triage-ledger';
  projectName: string;
  updatedAt: string;
  entries: TriageEntry[];
}

export interface TriageMatch {
  entry: TriageEntry;
  status: 'current' | 'stale' | 'unmatched';
  findingId?: string;
}

function fileDigests(finding: Finding): string[] {
  return [...new Set(finding.evidence.map((evidence) => evidence.fileDigest))].sort();
}

function sameValues(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function upsertTriageLedger(
  current: TriageLedger | undefined,
  report: AuditReport,
  input: {
    findingId: string;
    assessment: TriageAssessment;
    evidenceIds: string[];
    note: string;
    assessedAt?: string;
  },
): TriageLedger {
  if (current && current.projectName !== report.projectName)
    throw new Error('Triage ledger belongs to a different project.');
  const finding = report.findings.find((candidate) => candidate.id === input.findingId);
  if (!finding) throw new Error('Finding not found in the source audit report.');
  const citedIds = [...new Set(input.evidenceIds)].sort();
  const availableIds = new Set(finding.evidence.map((evidence) => evidence.id));
  if (!citedIds.length || citedIds.length > 16 || citedIds.some((id) => !availableIds.has(id)))
    throw new Error('Cite 1 to 16 evidence IDs from the selected finding.');
  const digests = fileDigests(finding);
  if (!digests.length) throw new Error('Finding has no source evidence digest.');
  const note = redact(input.note.trim());
  if (note.length < 12)
    throw new Error('Explain the assessment and evidence in at least 12 characters.');
  const assessedAt = input.assessedAt ?? new Date().toISOString();
  if (!Number.isFinite(Date.parse(assessedAt)))
    throw new Error('Assessment date must be valid ISO time.');
  const entry: TriageEntry = {
    fingerprint: finding.fingerprint,
    ruleId: finding.ruleId,
    evidenceFileDigests: digests,
    evidenceIds: citedIds,
    sourceAuditId: report.auditId,
    sourceSnapshotDigest: report.snapshotDigest,
    assessment: input.assessment,
    note,
    assessedAt: new Date(assessedAt).toISOString(),
    origin: 'external-agent',
  };
  return {
    schemaVersion: triageLedgerVersion,
    kind: 'codebasescan-triage-ledger',
    projectName: report.projectName,
    updatedAt: entry.assessedAt,
    entries: [
      ...(current?.entries.filter((item) => item.fingerprint !== entry.fingerprint) ?? []),
      entry,
    ].sort((left, right) => left.fingerprint.localeCompare(right.fingerprint)),
  };
}

export function matchTriageLedger(report: AuditReport, ledger: TriageLedger): TriageMatch[] {
  if (ledger.projectName !== report.projectName)
    throw new Error('Triage ledger belongs to a different project.');
  const findings = new Map(report.findings.map((finding) => [finding.fingerprint, finding]));
  return ledger.entries.map((entry) => {
    const finding = findings.get(entry.fingerprint);
    if (!finding) return { entry, status: 'unmatched' };
    const currentIds = new Set(finding.evidence.map((evidence) => evidence.id));
    const current =
      finding.ruleId === entry.ruleId &&
      sameValues(fileDigests(finding), entry.evidenceFileDigests) &&
      entry.evidenceIds.every((id) => currentIds.has(id));
    return { entry, status: current ? 'current' : 'stale', findingId: finding.id };
  });
}

export function transferCurrentTriage(
  source: AuditReport,
  target: AuditReport,
  ledger: TriageLedger,
): { ledger: TriageLedger; transferred: number; skipped: number } {
  const sourceMatches = matchTriageLedger(source, ledger);
  const currentEntries = sourceMatches
    .filter((item) => item.status === 'current')
    .map((item) => item.entry);
  const renamed: TriageLedger = {
    ...ledger,
    projectName: target.projectName,
    entries: currentEntries,
  };
  const targetMatches = matchTriageLedger(target, renamed);
  const entries = targetMatches
    .filter((item) => item.status === 'current')
    .map((item) => item.entry);
  if (!entries.length)
    throw new Error('No unchanged, evidence-matched triage entries to transfer.');
  return {
    ledger: { ...renamed, updatedAt: new Date().toISOString(), entries },
    transferred: entries.length,
    skipped: ledger.entries.length - entries.length,
  };
}
