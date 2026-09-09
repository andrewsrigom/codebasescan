import type { Finding, HttpProbeReport, ProjectProfile } from './types.ts';
import { effectiveEntrypointFacts } from './project-graph.ts';
import { severityRank } from './findings.ts';

function confidence(finding: Finding): NonNullable<Finding['confidence']> {
  if (finding.confidence) return finding.confidence;
  if (finding.source === 'http-probe') return 'high';
  if (['ast', 'next', 'react', 'osv', 'semgrep', 'gitleaks'].includes(finding.source))
    return 'medium';
  return 'low';
}

function runtimeExposure(report?: HttpProbeReport): Finding['exposure'] {
  if (!report) return 'unknown';
  try {
    const host = new URL(report.finalUrl).hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'local';
    return 'potentially_public';
  } catch {
    return 'unknown';
  }
}

function sourceExposure(finding: Finding, profile?: ProjectProfile): Finding['exposure'] {
  if (finding.source === 'react' || ['TW-NEXT004', 'TW-NEXT007'].includes(finding.ruleId))
    return 'potentially_public';
  if (!profile) return 'unknown';
  const evidenceFiles = new Set(finding.evidence.map((evidence) => evidence.file));
  const boundary = profile.entrypoints.find(
    (entrypoint) => entrypoint.kind !== 'middleware' && evidenceFiles.has(entrypoint.file),
  );
  if (!boundary) return 'unknown';
  const guarded = effectiveEntrypointFacts(profile, boundary).some((fact) =>
    ['authentication', 'authorization'].includes(fact.kind),
  );
  return guarded ? 'authenticated' : 'potentially_public';
}

function priority(finding: Finding): number {
  const base = [95, 78, 52, 28, 10][severityRank(finding.severity)] ?? 10;
  const exposure =
    finding.exposure === 'potentially_public'
      ? 10
      : finding.exposure === 'authenticated'
        ? 4
        : finding.exposure === 'local'
          ? -8
          : 0;
  const detectionConfidence =
    finding.confidence === 'high' ? 5 : finding.confidence === 'low' ? -10 : 0;
  const dependency =
    finding.vulnerability?.reachability === 'referenced'
      ? 7
      : finding.vulnerability?.relationship === 'direct'
        ? 3
        : 0;
  const nonRuntime = finding.evidence.every(
    (evidence) => evidence.scope === 'test' || evidence.scope === 'example',
  )
    ? -15
    : 0;
  return Math.max(
    0,
    Math.min(100, base + exposure + detectionConfidence + dependency + nonRuntime),
  );
}

export function enrichFindingQuality(
  findings: Finding[],
  profile?: ProjectProfile,
  httpProbe?: HttpProbeReport,
): Finding[] {
  return findings
    .map((finding) => {
      const enriched: Finding = {
        ...finding,
        confidence: confidence(finding),
        exposure:
          finding.source === 'http-probe'
            ? runtimeExposure(httpProbe)
            : sourceExposure(finding, profile),
      };
      enriched.priority = priority(enriched);
      return enriched;
    })
    .sort(
      (left, right) =>
        (right.priority ?? 0) - (left.priority ?? 0) || left.id.localeCompare(right.id),
    );
}
