import type { Dependency, Finding, Severity } from './types.ts';
import { severityRank } from './findings.ts';

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface NumericVersion {
  major: number;
  minor: number;
  patch: number;
  value: string;
}

export interface DependencyVersionPlan {
  version: string;
  advisoryCount: number;
  severityCounts: Record<Severity, number>;
  highestSeverity: Severity;
  relationship: 'direct' | 'transitive' | 'unknown';
  reachability: 'referenced' | 'not_found' | 'unknown';
  scopes: Dependency['scope'][];
  parentChains: string[][];
  fixCandidate?: string;
  fixCoverage: number;
  action: string;
  findings: Finding[];
}

export interface DependencyAdvisoryGroup {
  package: string;
  advisoryCount: number;
  pendingCount: number;
  highestSeverity: Severity;
  maxPriority: number;
  relationship: 'direct' | 'transitive' | 'unknown';
  reachability: 'referenced' | 'not_found' | 'unknown';
  affectedVersions: string[];
  versionPlans: DependencyVersionPlan[];
  findings: Finding[];
}

function numericVersion(value: string): NumericVersion | null {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z.-]+)?$/.exec(value.trim());
  if (!match) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  return { major, minor, patch, value };
}

function compareVersions(left: NumericVersion, right: NumericVersion): number {
  return left.major - right.major || left.minor - right.minor || left.patch - right.patch;
}

function severityCounts(findings: Finding[]): Record<Severity, number> {
  return Object.fromEntries(
    severities.map((severity) => [
      severity,
      findings.filter((finding) => finding.severity === severity).length,
    ]),
  ) as Record<Severity, number>;
}

function highestSeverity(findings: Finding[]): Severity {
  return (
    [...findings].sort(
      (left, right) => severityRank(left.severity) - severityRank(right.severity),
    )[0]?.severity ?? 'info'
  );
}

function relationship(findings: Finding[]): DependencyVersionPlan['relationship'] {
  const values = findings.map((finding) => finding.vulnerability?.relationship);
  if (values.includes('direct')) return 'direct';
  if (values.includes('transitive')) return 'transitive';
  return 'unknown';
}

function reachability(findings: Finding[]): DependencyVersionPlan['reachability'] {
  const values = findings.map((finding) => finding.vulnerability?.reachability);
  if (values.includes('referenced')) return 'referenced';
  if (values.length > 0 && values.every((value) => value === 'not_found')) return 'not_found';
  return 'unknown';
}

function fixPlan(findings: Finding[], version: string): { candidate?: string; coverage: number } {
  const current = numericVersion(version);
  if (!current) return { coverage: 0 };
  const candidates = findings.flatMap((finding) => {
    const compatible = (finding.vulnerability?.fixedVersions ?? [])
      .map(numericVersion)
      .filter((item): item is NumericVersion => Boolean(item))
      .filter((item) => item.major === current.major && compareVersions(item, current) > 0)
      .sort(compareVersions);
    return compatible[0] ? [compatible[0]] : [];
  });
  const candidate = [...candidates].sort(compareVersions).at(-1);
  return { ...(candidate ? { candidate: candidate.value } : {}), coverage: candidates.length };
}

function actionFor(input: {
  package: string;
  version: string;
  relationship: DependencyVersionPlan['relationship'];
  candidate?: string;
  coverage: number;
  total: number;
}): string {
  if (!input.candidate)
    return `No higher same-major OSV fixed event was found for ${input.package}@${input.version}. Review the supported branch, parent dependency, or a major upgrade.`;
  const operation =
    input.relationship === 'direct'
      ? `Evaluate a direct upgrade to ${input.package}@${input.candidate}`
      : `Update the parent dependency or lockfile until ${input.package}@${input.candidate} is resolved`;
  const coverage = `${input.coverage}/${input.total} ${input.total === 1 ? 'advisory has' : 'advisories have'} a compatible fixed event`;
  const remainder =
    input.coverage === input.total
      ? ''
      : `; ${input.total - input.coverage} still ${input.total - input.coverage === 1 ? 'requires' : 'require'} branch or vendor review`;
  return `${operation}; ${coverage}${remainder}. Re-run OSV after the lockfile changes.`;
}

function versionPlan(
  packageName: string,
  version: string,
  findings: Finding[],
  dependencies: Dependency[],
): DependencyVersionPlan {
  const dependencyRelationship = relationship(findings);
  const plan = fixPlan(findings, version);
  const scopes = [
    ...new Set(
      dependencies
        .filter(
          (dependency) => dependency.name === packageName && dependency.resolvedVersion === version,
        )
        .map((dependency) => dependency.scope),
    ),
  ];
  const parentChains = dependencies
    .filter(
      (dependency) => dependency.name === packageName && dependency.resolvedVersion === version,
    )
    .flatMap((dependency) => dependency.parentChains ?? [])
    .filter(
      (chain, index, chains) =>
        chains.findIndex((candidate) => candidate.join('\u0000') === chain.join('\u0000')) ===
        index,
    )
    .slice(0, 3);
  return {
    version,
    advisoryCount: findings.length,
    severityCounts: severityCounts(findings),
    highestSeverity: highestSeverity(findings),
    relationship: dependencyRelationship,
    reachability: reachability(findings),
    scopes,
    parentChains,
    ...(plan.candidate ? { fixCandidate: plan.candidate } : {}),
    fixCoverage: plan.coverage,
    action: actionFor({
      package: packageName,
      version,
      relationship: dependencyRelationship,
      candidate: plan.candidate,
      coverage: plan.coverage,
      total: findings.length,
    }),
    findings,
  };
}

export function groupDependencyAdvisories(
  findings: Finding[],
  dependencies: Dependency[] = [],
): DependencyAdvisoryGroup[] {
  const byPackage = new Map<string, Finding[]>();
  for (const finding of findings) {
    const packageName = finding.vulnerability?.package;
    if (!packageName) continue;
    byPackage.set(packageName, [...(byPackage.get(packageName) ?? []), finding]);
  }
  return [...byPackage.entries()]
    .map(([packageName, packageFindings]) => {
      const byVersion = new Map<string, Finding[]>();
      for (const finding of packageFindings) {
        const version = finding.vulnerability!.version;
        byVersion.set(version, [...(byVersion.get(version) ?? []), finding]);
      }
      const versionPlans = [...byVersion.entries()]
        .map(([version, versionFindings]) =>
          versionPlan(packageName, version, versionFindings, dependencies),
        )
        .sort((left, right) => left.version.localeCompare(right.version));
      return {
        package: packageName,
        advisoryCount: packageFindings.length,
        pendingCount: packageFindings.filter((finding) => finding.disposition === 'needs_review')
          .length,
        highestSeverity: highestSeverity(packageFindings),
        maxPriority: Math.max(...packageFindings.map((finding) => finding.priority ?? 0)),
        relationship: relationship(packageFindings),
        reachability: reachability(packageFindings),
        affectedVersions: versionPlans.map((plan) => plan.version),
        versionPlans,
        findings: packageFindings,
      } satisfies DependencyAdvisoryGroup;
    })
    .sort(
      (left, right) =>
        right.maxPriority - left.maxPriority ||
        severityRank(left.highestSeverity) - severityRank(right.highestSeverity) ||
        Number(right.relationship === 'direct') - Number(left.relationship === 'direct') ||
        right.advisoryCount - left.advisoryCount ||
        left.package.localeCompare(right.package),
    );
}
