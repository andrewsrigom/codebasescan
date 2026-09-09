import type { ProjectEntrypoint, ProjectFact, ProjectProfile } from './types.ts';

export const mutatingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
export const sensitiveProjectFactKinds = new Set<ProjectFact['kind']>([
  'database',
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
  if (entrypoint.kind !== 'next-route') return entrypoint.symbolIds;
  return entrypoint.symbolIds.filter((id) => {
    const symbol = profile.symbols.find((item) => item.id === id);
    return symbol ? mutatingMethods.has(symbol.name) : false;
  });
}

export function reachableFacts(
  profile: ProjectProfile,
  entrypoint: ProjectEntrypoint,
  maximumDepth = 2,
): ProjectFact[] {
  const roots = entrypointRoots(profile, entrypoint);
  const visited = new Set(roots);
  let frontier = new Set(roots);
  const edgesByCaller = new Map<string, string[]>();
  for (const edge of profile.calls) {
    if (!edge.callerSymbolId || !edge.targetSymbolId) continue;
    edgesByCaller.set(edge.callerSymbolId, [
      ...(edgesByCaller.get(edge.callerSymbolId) ?? []),
      edge.targetSymbolId,
    ]);
  }
  for (let depth = 0; depth < maximumDepth && frontier.size; depth++) {
    const next = new Set<string>();
    for (const caller of frontier)
      for (const target of edgesByCaller.get(caller) ?? [])
        if (!visited.has(target)) {
          visited.add(target);
          next.add(target);
        }
    frontier = next;
  }
  return profile.facts.filter((fact) => fact.ownerSymbolId && visited.has(fact.ownerSymbolId));
}

export function sensitiveFacts(facts: ProjectFact[]): ProjectFact[] {
  return facts.filter((fact) => sensitiveProjectFactKinds.has(fact.kind));
}
