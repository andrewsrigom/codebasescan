import { severityRank } from './findings.ts';
import type { AuditComparison, AuditReport, CoverageStatus, Finding, Severity } from './types.ts';

export const policyProfiles = ['advisory', 'balanced', 'strict'] as const;
export type PolicyProfile = (typeof policyProfiles)[number];
export const policyResultVersion = 1 as const;

export interface PolicyResult {
  schemaVersion: typeof policyResultVersion;
  kind: 'traceward-policy-result';
  generatedAt: string;
  auditId: string;
  snapshotDigest: string;
  profile: PolicyProfile;
  decision: 'advisory' | 'pass' | 'fail';
  exitCode: 0 | 1 | 2;
  baselineAuditId?: string;
  criteria: {
    minimumSeverity: Severity | null;
    minimumConfidence: 'medium' | null;
    findingScope: 'all-unresolved' | 'new-only';
    coverageGate: 'none' | 'failed-or-truncated' | 'partial-failed-or-truncated';
  };
  summary: {
    reportFindings: number;
    consideredFindings: number;
    excludedLegacyFindings: number;
    excludedByDisposition: number;
    excludedByActiveSuppression: number;
    matchedFindings: number;
    gatedFindings: number;
    coverageIssues: number;
    blockingCoverageIssues: number;
  };
  matchedFindingIds: string[];
  gatedFindingIds: string[];
  coverageIssues: {
    id: string;
    status: CoverageStatus;
    blocking: boolean;
    detail: string;
  }[];
  limitations: string[];
}

interface PolicyDefinition {
  minimumSeverity: Severity | null;
  minimumConfidence: 'medium' | null;
  newOnlyWhenBaseline: boolean;
  coverageGate: PolicyResult['criteria']['coverageGate'];
}

const definitions: Record<PolicyProfile, PolicyDefinition> = {
  advisory: {
    minimumSeverity: null,
    minimumConfidence: null,
    newOnlyWhenBaseline: false,
    coverageGate: 'none',
  },
  balanced: {
    minimumSeverity: 'high',
    minimumConfidence: 'medium',
    newOnlyWhenBaseline: true,
    coverageGate: 'failed-or-truncated',
  },
  strict: {
    minimumSeverity: 'medium',
    minimumConfidence: null,
    newOnlyWhenBaseline: false,
    coverageGate: 'partial-failed-or-truncated',
  },
};

function activeSuppression(finding: Finding, at: string): boolean {
  if (!finding.suppression) return false;
  if (!finding.suppression.expiresAt) return true;
  return Date.parse(finding.suppression.expiresAt) > Date.parse(at);
}

function meetsFindingCriteria(finding: Finding, definition: PolicyDefinition): boolean {
  if (
    definition.minimumSeverity &&
    severityRank(finding.severity) > severityRank(definition.minimumSeverity)
  )
    return false;
  if (
    definition.minimumConfidence === 'medium' &&
    finding.confidence !== 'medium' &&
    finding.confidence !== 'high'
  )
    return false;
  return true;
}

function blocksCoverage(
  status: CoverageStatus,
  coverageGate: PolicyDefinition['coverageGate'],
): boolean {
  if (coverageGate === 'none') return false;
  if (status === 'FAILED') return true;
  return coverageGate === 'partial-failed-or-truncated' && status === 'PARTIAL';
}

export function buildPolicyResult(
  report: AuditReport,
  profile: PolicyProfile,
  comparison?: AuditComparison | null,
): PolicyResult {
  if (comparison && comparison.currentAuditId !== report.auditId)
    throw new Error('Policy comparison does not belong to the evaluated audit.');

  const definition = definitions[profile];
  const useNewOnly = Boolean(comparison && definition.newOnlyWhenBaseline);
  const newFingerprints = new Set(comparison?.newFindings.map((finding) => finding.fingerprint));
  const scoped = useNewOnly
    ? report.findings.filter((finding) => newFingerprints.has(finding.fingerprint))
    : report.findings;
  const excludedByDisposition = scoped.filter((finding) =>
    ['fixed', 'false_positive', 'accepted_risk'].includes(finding.disposition),
  ).length;
  const unresolved = scoped.filter(
    (finding) => !['fixed', 'false_positive', 'accepted_risk'].includes(finding.disposition),
  );
  const excludedByActiveSuppression = unresolved.filter((finding) =>
    activeSuppression(finding, report.createdAt),
  ).length;
  const eligible = unresolved.filter((finding) => !activeSuppression(finding, report.createdAt));
  const matched = definition.minimumSeverity
    ? eligible.filter((finding) => meetsFindingCriteria(finding, definition))
    : eligible;

  const coverageIssues = (report.coverage ?? [])
    .filter((capability) => capability.status !== 'COMPLETE')
    .map((capability) => ({
      id: capability.id,
      status: capability.status,
      blocking: blocksCoverage(capability.status, definition.coverageGate),
      detail: capability.detail,
    }));
  if (report.truncated)
    coverageIssues.unshift({
      id: 'source-snapshot',
      status: 'PARTIAL',
      blocking: definition.coverageGate !== 'none',
      detail: 'The captured source snapshot was truncated; omitted files remain unverified.',
    });

  const blockingCoverageIssues = coverageIssues.filter((issue) => issue.blocking).length;
  const gated = profile === 'advisory' ? [] : matched;
  const exitCode: PolicyResult['exitCode'] =
    profile === 'advisory' ? 0 : blockingCoverageIssues ? 2 : gated.length ? 1 : 0;
  return {
    schemaVersion: policyResultVersion,
    kind: 'traceward-policy-result',
    generatedAt: report.createdAt,
    auditId: report.auditId,
    snapshotDigest: report.snapshotDigest,
    profile,
    decision: profile === 'advisory' ? 'advisory' : exitCode === 0 ? 'pass' : 'fail',
    exitCode,
    ...(comparison ? { baselineAuditId: comparison.baseAuditId } : {}),
    criteria: {
      minimumSeverity: definition.minimumSeverity,
      minimumConfidence: definition.minimumConfidence,
      findingScope: useNewOnly ? 'new-only' : 'all-unresolved',
      coverageGate: definition.coverageGate,
    },
    summary: {
      reportFindings: report.findings.length,
      consideredFindings: scoped.length,
      excludedLegacyFindings: report.findings.length - scoped.length,
      excludedByDisposition,
      excludedByActiveSuppression,
      matchedFindings: matched.length,
      gatedFindings: gated.length,
      coverageIssues: coverageIssues.length,
      blockingCoverageIssues,
    },
    matchedFindingIds: matched.map((finding) => finding.id).sort(),
    gatedFindingIds: gated.map((finding) => finding.id).sort(),
    coverageIssues,
    limitations: [
      'Policy evaluates captured findings and coverage metadata; it does not certify security or compliance.',
      'Unperformed, disabled, and unsupported capabilities remain visible but do not block built-in profiles.',
      'Suppression expiry is evaluated against the immutable audit creation time for deterministic replay.',
    ],
  };
}
