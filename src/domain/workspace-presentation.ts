import { effectiveEntrypointFacts, sensitiveProjectFactKinds } from './project-graph.ts';
import type { Audit, ProjectProfile, ProjectProfilePresentation } from './types.ts';

export function presentProjectProfile(
  profile: ProjectProfile | undefined,
): ProjectProfilePresentation | undefined {
  if (!profile) return undefined;
  const factCounts = new Map<ProjectProfile['facts'][number]['kind'], number>();
  for (const fact of profile.facts) factCounts.set(fact.kind, (factCounts.get(fact.kind) ?? 0) + 1);
  return {
    status: profile.status,
    languages: profile.languages,
    frameworks: profile.frameworks,
    entrypoints: profile.entrypoints.map((entrypoint) => {
      const facts = effectiveEntrypointFacts(profile, entrypoint);
      return {
        ...entrypoint,
        factKinds: [...new Set(facts.map((fact) => fact.kind))],
        sensitiveOperations: facts.filter((fact) => sensitiveProjectFactKinds.has(fact.kind))
          .length,
      };
    }),
    symbolCount: profile.symbols.length,
    callCount: profile.calls.length,
    factCount: profile.facts.length,
    factCounts: [...factCounts.entries()].sort((left, right) => right[1] - left[1]),
    filesAnalyzed: profile.filesAnalyzed,
    nodesAnalyzed: profile.nodesAnalyzed,
    issues: profile.issues,
    truncated: profile.truncated,
  };
}

export function presentAudit(audit: Audit): {
  audit: Audit;
  projectProfile: ProjectProfilePresentation | undefined;
} {
  return {
    audit: audit.report
      ? { ...audit, report: { ...audit.report, projectProfile: undefined } }
      : audit,
    projectProfile: presentProjectProfile(audit.report?.projectProfile),
  };
}
