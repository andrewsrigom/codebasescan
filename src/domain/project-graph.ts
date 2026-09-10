import type { ProjectCallEdge, ProjectEntrypoint, ProjectFact, ProjectProfile } from './types.ts';

export const mutatingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
export const maximumCallDepth = 5;
export const sensitiveProjectFactKinds = new Set<ProjectFact['kind']>([
  'database',
  'billing',
  'raw-sql',
  'command-execution',
  'file-access',
]);

export function isMutatingEntrypoint(entrypoint: ProjectEntrypoint): boolean {
  if (entrypoint.kind === 'server-action') return true;
  return entrypoint.methods.some((method) => mutatingMethods.has(method));
}

export function isWebhookEntrypoint(entrypoint: ProjectEntrypoint): boolean {
  const route = entrypoint.route ?? '';
  if (/\/(?:webhook|callback)(?:\/|$)/i.test(route)) return true;
  if (/\/api\/(?:webhooks|callbacks)(?:\/|$)/i.test(route)) return true;
  return /\/(?:webhooks|callbacks)\/(?!\[|:)[^/]+(?:\/|$)/i.test(route);
}

export function isAdministrativeEntrypoint(entrypoint: ProjectEntrypoint): boolean {
  return /(?:^|[/._-])(?:admin|internal)(?:[/._-]|$)/i.test(
    `${entrypoint.route ?? ''}/${entrypoint.file}/${entrypoint.name}`,
  );
}

export function entrypointRoots(profile: ProjectProfile, entrypoint: ProjectEntrypoint): string[] {
  if (entrypoint.kind !== 'next-route' || entrypoint.methods.length <= 1)
    return entrypoint.symbolIds;
  return entrypoint.symbolIds.filter((id) => {
    const symbol = profile.symbols.find((item) => item.id === id);
    return symbol ? entrypoint.methods.includes(symbol.name) : false;
  });
}

function graphEdges(profile: ProjectProfile): Map<string, ProjectCallEdge[]> {
  const edges = new Map<string, ProjectCallEdge[]>();
  for (const edge of profile.calls) {
    if (!edge.callerSymbolId || !edge.targetSymbolId) continue;
    edges.set(edge.callerSymbolId, [...(edges.get(edge.callerSymbolId) ?? []), edge]);
  }
  return edges;
}

function reachableSymbols(
  profile: ProjectProfile,
  entrypoint: ProjectEntrypoint,
  maximumDepth = maximumCallDepth,
): Set<string> {
  const roots = entrypointRoots(profile, entrypoint);
  const visited = new Set(roots);
  let frontier = new Set(roots);
  const edgesByCaller = graphEdges(profile);
  for (let depth = 0; depth < maximumDepth && frontier.size; depth++) {
    const next = new Set<string>();
    for (const caller of frontier)
      for (const edge of edgesByCaller.get(caller) ?? [])
        if (edge.targetSymbolId && !visited.has(edge.targetSymbolId)) {
          visited.add(edge.targetSymbolId);
          next.add(edge.targetSymbolId);
        }
    frontier = next;
  }
  return visited;
}

export function reachableFacts(
  profile: ProjectProfile,
  entrypoint: ProjectEntrypoint,
  maximumDepth = maximumCallDepth,
): ProjectFact[] {
  const visited = reachableSymbols(profile, entrypoint, maximumDepth);
  return profile.facts.filter((fact) => fact.ownerSymbolId && visited.has(fact.ownerSymbolId));
}

function matcherCoversRoute(matcher: string, route: string): boolean {
  const normalized = matcher.split('?')[0]?.trim() ?? '';
  if (!normalized.startsWith('/')) return false;
  if (normalized === '/:path*' || normalized === '/(.*)' || normalized === '/**') return true;
  const marker = normalized.search(/[:*[(]/);
  const prefix = marker < 0 ? normalized : normalized.slice(0, marker);
  if (!prefix) return false;
  return marker < 0 ? route === prefix : route.startsWith(prefix);
}

export function middlewareFacts(
  profile: ProjectProfile,
  entrypoint: ProjectEntrypoint,
): ProjectFact[] {
  if (!entrypoint.route) return [];
  const middleware = profile.entrypoints.filter(
    (candidate) =>
      candidate.kind === 'middleware' &&
      (!candidate.matchers?.length ||
        candidate.matchers.some((matcher) => matcherCoversRoute(matcher, entrypoint.route!))),
  );
  return middleware.flatMap((candidate) => reachableFacts(profile, candidate));
}

export function effectiveEntrypointFacts(
  profile: ProjectProfile,
  entrypoint: ProjectEntrypoint,
): ProjectFact[] {
  return [
    ...new Map(
      [...reachableFacts(profile, entrypoint), ...middlewareFacts(profile, entrypoint)].map(
        (fact) => [fact.id, fact],
      ),
    ).values(),
  ];
}

export function callPathToFact(
  profile: ProjectProfile,
  entrypoint: ProjectEntrypoint,
  fact: ProjectFact,
  maximumDepth = maximumCallDepth,
): ProjectCallEdge[] {
  if (!fact.ownerSymbolId) return [];
  const roots = entrypointRoots(profile, entrypoint);
  if (roots.includes(fact.ownerSymbolId)) return [];
  const edgesByCaller = graphEdges(profile);
  const visited = new Set(roots);
  const parent = new Map<string, ProjectCallEdge>();
  let frontier = new Set(roots);
  for (let depth = 0; depth < maximumDepth && frontier.size; depth++) {
    const next = new Set<string>();
    for (const caller of frontier)
      for (const edge of edgesByCaller.get(caller) ?? []) {
        const target = edge.targetSymbolId;
        if (!target || visited.has(target)) continue;
        visited.add(target);
        parent.set(target, edge);
        if (target === fact.ownerSymbolId) {
          const path: ProjectCallEdge[] = [];
          let cursor: string | undefined = target;
          while (cursor && parent.has(cursor)) {
            const step: ProjectCallEdge = parent.get(cursor)!;
            path.unshift(step);
            cursor = step.callerSymbolId;
          }
          return path;
        }
        next.add(target);
      }
    frontier = next;
  }
  return [];
}

export function sensitiveFacts(facts: ProjectFact[]): ProjectFact[] {
  return facts.filter((fact) => sensitiveProjectFactKinds.has(fact.kind));
}
