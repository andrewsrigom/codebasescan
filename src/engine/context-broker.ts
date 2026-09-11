import { digest } from '../domain/findings.ts';
import { agentReviewDepthLimits, type AgentReviewDepth } from '../domain/agent-depth.ts';
import type { Finding, ProjectProfile, Snapshot, SourceFile } from '../domain/types.ts';
import { redact } from '../security/redact.ts';

export type ContextKind = 'evidence' | 'entrypoint' | 'symbol' | 'fact' | 'call' | 'search';

export interface ContextDescriptor {
  id: string;
  kind: ContextKind;
  label: string;
  file: string;
  line: number;
}

export interface ContextDelivery {
  context: string;
  deliveredIds: string[];
  files: string[];
  characters: number;
  truncated: boolean;
}

const maximumItemCharacters = 6_000;

function sourceLines(file: SourceFile, startLine: number, endLine: number): string {
  const lines = file.content.split(/\r?\n/);
  const start = Math.max(1, startLine);
  const end = Math.min(lines.length, Math.max(start, endLine));
  return lines
    .slice(start - 1, end)
    .map((line, offset) => `${start + offset}: ${line}`)
    .join('\n');
}

function boundedExcerpt(file: SourceFile, line: number, radius = 24): string {
  return sourceLines(file, Math.max(1, line - radius), line + radius).slice(
    0,
    maximumItemCharacters,
  );
}

function relatedProfileIds(finding: Finding, profile?: ProjectProfile): Set<string> {
  if (!profile) return new Set();
  const evidenceFiles = new Set(finding.evidence.map((item) => item.file));
  const relevantSymbols = new Set(
    profile.symbols.filter((item) => evidenceFiles.has(item.file)).map((item) => item.id),
  );
  const relevantEntrypoints = profile.entrypoints.filter(
    (item) => evidenceFiles.has(item.file) || item.symbolIds.some((id) => relevantSymbols.has(id)),
  );
  for (const entrypoint of relevantEntrypoints)
    for (const symbolId of entrypoint.symbolIds) relevantSymbols.add(symbolId);

  let frontier = new Set(relevantSymbols);
  for (let depth = 0; depth < 2 && frontier.size; depth++) {
    const next = new Set<string>();
    for (const edge of profile.calls) {
      if (!edge.callerSymbolId || !edge.targetSymbolId || !frontier.has(edge.callerSymbolId))
        continue;
      if (!relevantSymbols.has(edge.targetSymbolId)) next.add(edge.targetSymbolId);
      relevantSymbols.add(edge.targetSymbolId);
    }
    frontier = next;
  }

  const ids = new Set<string>();
  for (const entrypoint of relevantEntrypoints) ids.add(entrypoint.id);
  for (const symbol of profile.symbols) if (relevantSymbols.has(symbol.id)) ids.add(symbol.id);
  for (const fact of profile.facts)
    if (
      evidenceFiles.has(fact.file) ||
      (fact.ownerSymbolId && relevantSymbols.has(fact.ownerSymbolId))
    )
      ids.add(fact.id);
  for (const call of profile.calls)
    if (
      (call.callerSymbolId && relevantSymbols.has(call.callerSymbolId)) ||
      (call.targetSymbolId && relevantSymbols.has(call.targetSymbolId))
    )
      ids.add(call.id);
  return ids;
}

function normalizedSearchQuery(query: string): { label: string; terms: string[] } | null {
  const label = query.trim().toLowerCase();
  if (
    label.length < 3 ||
    label.length > 80 ||
    label.includes('..') ||
    /^[a-z]:[\\/]/i.test(label) ||
    label.startsWith('/') ||
    label.startsWith('\\')
  )
    return null;
  const terms = label
    .split(/[^a-z0-9_$@.-]+/i)
    .filter((term) => term.length >= 2)
    .slice(0, 6);
  return terms.length ? { label, terms } : null;
}

export function createContextBroker(
  snapshot: Snapshot,
  finding: Finding,
  profile?: ProjectProfile,
  depth: AgentReviewDepth = 'standard',
) {
  const limits = agentReviewDepthLimits[depth];
  const files = new Map(snapshot.files.map((file) => [file.path, file]));
  const descriptors = new Map<string, ContextDescriptor>();
  const renderers = new Map<string, () => string>();

  for (const evidence of finding.evidence) {
    const file = files.get(evidence.file);
    if (!file) continue;
    descriptors.set(evidence.id, {
      id: evidence.id,
      kind: 'evidence',
      label: evidence.observation.slice(0, 180),
      file: evidence.file,
      line: evidence.startLine,
    });
    renderers.set(evidence.id, () =>
      sourceLines(file, evidence.startLine, evidence.endLine).slice(0, maximumItemCharacters),
    );
  }

  const relatedIds = relatedProfileIds(finding, profile);
  if (profile) {
    for (const entrypoint of profile.entrypoints) {
      if (!relatedIds.has(entrypoint.id)) continue;
      const file = files.get(entrypoint.file);
      if (!file) continue;
      descriptors.set(entrypoint.id, {
        id: entrypoint.id,
        kind: 'entrypoint',
        label: `${entrypoint.kind} ${entrypoint.methods.join(',') || entrypoint.name}`,
        file: entrypoint.file,
        line: entrypoint.line,
      });
      renderers.set(entrypoint.id, () => boundedExcerpt(file, entrypoint.line));
    }
    for (const symbol of profile.symbols) {
      if (!relatedIds.has(symbol.id)) continue;
      const file = files.get(symbol.file);
      if (!file) continue;
      descriptors.set(symbol.id, {
        id: symbol.id,
        kind: 'symbol',
        label: `${symbol.kind} ${symbol.name}`,
        file: symbol.file,
        line: symbol.line,
      });
      renderers.set(symbol.id, () => boundedExcerpt(file, symbol.line));
    }
    for (const fact of profile.facts) {
      if (!relatedIds.has(fact.id)) continue;
      const file = files.get(fact.file);
      if (!file) continue;
      descriptors.set(fact.id, {
        id: fact.id,
        kind: 'fact',
        label: `${fact.kind}: ${fact.signal}`.slice(0, 180),
        file: fact.file,
        line: fact.line,
      });
      renderers.set(fact.id, () => boundedExcerpt(file, fact.line));
    }
    for (const call of profile.calls) {
      if (!relatedIds.has(call.id)) continue;
      const file = files.get(call.file);
      if (!file) continue;
      descriptors.set(call.id, {
        id: call.id,
        kind: 'call',
        label: `call ${call.callee}`.slice(0, 180),
        file: call.file,
        line: call.line,
      });
      renderers.set(call.id, () => boundedExcerpt(file, call.line, 12));
    }
  }

  const initialIds = finding.evidence
    .map((item) => item.id)
    .filter((id) => descriptors.has(id))
    .slice(0, limits.maximumInitialItems);

  function catalog(): ContextDescriptor[] {
    return [...descriptors.values()]
      .sort((left, right) => {
        const priority = (item: ContextDescriptor) =>
          item.kind === 'evidence' ? 0 : item.kind === 'search' ? 1 : 2;
        return (
          priority(left) - priority(right) ||
          left.file.localeCompare(right.file) ||
          left.line - right.line
        );
      })
      .slice(0, limits.maximumCatalogItems);
  }

  function search(queries: string[], previousIds: string[] = []): string[] {
    if (!limits.maximumSearchQueries || !limits.maximumSearchResults) return [];
    const normalized = [...new Set(queries)]
      .flatMap((query) => {
        const value = normalizedSearchQuery(query);
        return value ? [value] : [];
      })
      .slice(0, limits.maximumSearchQueries);
    const orderedFiles = [...files.values()].sort((left, right) =>
      left.path.localeCompare(right.path),
    );
    const matched: string[] = [];
    let searchedCharacters = 0;
    for (const query of normalized) {
      for (const file of orderedFiles) {
        if (
          searchedCharacters >= limits.maximumSearchCharacters ||
          matched.length >= limits.maximumSearchResults
        )
          break;
        searchedCharacters += file.content.length;
        const pathText = file.path.toLowerCase();
        const lines = file.content.split(/\r?\n/);
        for (let index = 0; index < lines.length; index++) {
          if (matched.length >= limits.maximumSearchResults) break;
          const searchable = `${pathText} ${lines[index]!.toLowerCase()}`;
          if (
            !searchable.includes(query.label) &&
            !query.terms.every((term) => searchable.includes(term))
          )
            continue;
          const line = index + 1;
          const id = `ctx-search-${digest(`${query.label}:${file.path}:${line}`).slice(0, 24)}`;
          descriptors.set(id, {
            id,
            kind: 'search',
            label: `search "${query.label}"`,
            file: file.path,
            line,
          });
          renderers.set(id, () => boundedExcerpt(file, line, 12));
          matched.push(id);
        }
      }
    }
    const allowed = new Set(catalog().map((item) => item.id));
    const previous = new Set(previousIds);
    return matched.filter((id) => allowed.has(id) && !previous.has(id));
  }

  function collect(
    requestedIds: string[],
    previousIds: string[] = [],
    previousCharacters = 0,
    initial = false,
  ): ContextDelivery {
    const maximumItems = initial ? limits.maximumInitialItems : limits.maximumRequestedItems;
    const remaining = Math.max(0, limits.maximumContextCharacters - previousCharacters);
    const seen = new Set(previousIds);
    const allowedIds = new Set(catalog().map((item) => item.id));
    const fresh = [...new Set(requestedIds)]
      .filter((id) => allowedIds.has(id) && !seen.has(id))
      .slice(0, maximumItems);
    const chunks: string[] = [];
    const deliveredIds: string[] = [];
    const deliveredFiles: string[] = [];
    let used = 0;
    let truncated = false;
    for (const id of fresh) {
      const descriptor = descriptors.get(id);
      const render = renderers.get(id);
      if (!descriptor || !render || used >= remaining) {
        truncated = true;
        break;
      }
      const header = JSON.stringify({
        contextId: id,
        kind: descriptor.kind,
        file: descriptor.file,
        line: descriptor.line,
        policy: 'untrusted_repository_data',
      });
      const raw = redact(render());
      const available = remaining - used - header.length - 2;
      if (available <= 0) {
        truncated = true;
        break;
      }
      const body = raw.slice(0, available);
      if (body.length < raw.length) truncated = true;
      const chunk = `${header}\n${body}`;
      chunks.push(chunk);
      used += chunk.length + 1;
      deliveredIds.push(id);
      deliveredFiles.push(descriptor.file);
    }
    return {
      context: chunks.join('\n'),
      deliveredIds,
      files: [...new Set(deliveredFiles)],
      characters: chunks.join('\n').length,
      truncated,
    };
  }

  return {
    get catalog() {
      return catalog();
    },
    initialIds,
    collect,
    search,
  };
}

const standardLimits = agentReviewDepthLimits.standard;
export const contextBrokerLimits = {
  maximumContextCharacters: standardLimits.maximumContextCharacters,
  maximumInitialItems: standardLimits.maximumInitialItems,
  maximumRequestedItems: standardLimits.maximumRequestedItems,
  maximumCatalogItems: standardLimits.maximumCatalogItems,
  byDepth: agentReviewDepthLimits,
};
