import type { Finding, ProjectProfile, Snapshot, SourceFile } from '../domain/types.ts';
import { redact } from '../security/redact.ts';

export type ContextKind = 'evidence' | 'entrypoint' | 'symbol' | 'fact' | 'call';

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

const maximumContextCharacters = 16_000;
const maximumInitialItems = 12;
const maximumRequestedItems = 2;
const maximumCatalogItems = 60;
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

  // Follow only profiler-resolved local calls, with a small fixed depth.
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

export function createContextBroker(
  snapshot: Snapshot,
  finding: Finding,
  profile?: ProjectProfile,
) {
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
    .slice(0, maximumInitialItems);
  const catalog = [...descriptors.values()]
    .sort((left, right) => {
      const leftEvidence = left.kind === 'evidence' ? 0 : 1;
      const rightEvidence = right.kind === 'evidence' ? 0 : 1;
      return (
        leftEvidence - rightEvidence ||
        left.file.localeCompare(right.file) ||
        left.line - right.line
      );
    })
    .slice(0, maximumCatalogItems);
  const allowedIds = new Set(catalog.map((item) => item.id));

  function collect(
    requestedIds: string[],
    previousIds: string[] = [],
    previousCharacters = 0,
    initial = false,
  ): ContextDelivery {
    const maximumItems = initial ? maximumInitialItems : maximumRequestedItems;
    const remaining = Math.max(0, maximumContextCharacters - previousCharacters);
    const seen = new Set(previousIds);
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

  return { catalog, initialIds, collect };
}

export const contextBrokerLimits = {
  maximumContextCharacters,
  maximumInitialItems,
  maximumRequestedItems,
  maximumCatalogItems,
};
