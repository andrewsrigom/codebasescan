import { digest } from './findings.ts';
import type {
  ProjectDataMap,
  ProjectDataMapEntry,
  ProjectDataOperation,
  ProjectDeclaredContext,
  ProjectFact,
} from './types.ts';

const maximumEntries = 2_000;

function operation(fact: ProjectFact): ProjectDataOperation | null {
  if (fact.kind === 'secret-access') return 'sensitive-read';
  if (fact.kind === 'database') return 'persistent-storage';
  if (fact.kind === 'browser-storage') return 'browser-storage';
  if (fact.kind === 'cookie') return 'cookie';
  if (fact.kind === 'response') return 'response';
  if (fact.kind === 'logging') return 'log';
  if (fact.kind === 'redirect') return 'url-or-redirect';
  if (fact.kind === 'outbound-request') return 'outbound-transfer';
  if (fact.kind === 'billing') return 'financial-operation';
  return null;
}

function dataClasses(operation: ProjectDataOperation): ProjectDataMapEntry['dataClasses'] {
  if (operation === 'sensitive-read') return ['credentials'];
  if (operation === 'financial-operation') return ['financial'];
  return ['unknown'];
}

export function buildProjectDataMap(
  facts: ProjectFact[],
  context?: ProjectDeclaredContext,
): ProjectDataMap {
  const entries: ProjectDataMapEntry[] = [];
  const summary: ProjectDataMap['summary'] = {};
  for (const fact of facts) {
    const mappedOperation = operation(fact);
    if (!mappedOperation) continue;
    summary[mappedOperation] = (summary[mappedOperation] ?? 0) + 1;
    if (entries.length >= maximumEntries) continue;
    entries.push({
      id: `data-${digest(`${fact.id}:${mappedOperation}`).slice(0, 16)}`,
      operation: mappedOperation,
      file: fact.file,
      line: fact.line,
      signal: fact.signal,
      sourceFactId: fact.id,
      provenance: 'observed',
      dataClasses: dataClasses(mappedOperation),
    });
  }
  const total = Object.values(summary).reduce((sum, count) => sum + (count ?? 0), 0);
  return {
    schemaVersion: 1,
    entries,
    summary,
    declaredData: context?.sensitiveData ?? [],
    declaredBoundaries: {
      storage: context?.storageBoundaries ?? [],
      externalServices: context?.externalServices ?? [],
    },
    truncated: total > entries.length,
  };
}
