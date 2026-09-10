import ts from 'typescript';
import { digest } from '../domain/findings.ts';
import type {
  ProjectCallEdge,
  ProjectEntrypoint,
  ProjectFact,
  ProjectProfile,
  ProjectSymbol,
  ScannerRun,
  Snapshot,
  SourceFile,
  WebhookContractAnalysis,
  WebhookEndpointContract,
  WebhookEventReference,
} from '../domain/types.ts';

const sourcePattern = /\.(?:[cm]?[jt]sx?)$/i;
const routeKinds = new Set<ProjectEntrypoint['kind']>([
  'next-route',
  'next-pages-api',
  'express-route',
]);
const webhookPattern = /(?:^|[\/_.,-])webhooks?(?:[\/_.,-]|$)|(?:^|\/)hooks?(?:\/|$)/i;
const callbackPattern = /(?:^|[\/_.,-])callback(?:[\/_.,-]|$)/i;
const eventProperties = new Set(['type', 'event', 'eventtype', 'topic']);
const dispatchPattern = /(?:webhook|emit|publish|dispatch|deliver|trigger|enqueue|send)/i;
const maximumEndpoints = 200;
const maximumTraversalDepth = 8;
const maximumReachableSymbols = 1_000;
const maximumCallEdges = 5_000;
const maximumEventReferences = 2_000;

function stableId(...parts: string[]): string {
  return digest(parts.join(':')).slice(0, 20);
}

function scriptKind(file: string): ts.ScriptKind {
  const lower = file.toLowerCase();
  if (lower.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (lower.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (/\.[cm]?js$/.test(lower)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function propertyName(node: ts.Node): string | null {
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node))
    return node.text.toLowerCase();
  return null;
}

function stringValue(node: ts.Expression): string | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

function discriminantProperty(node: ts.Expression): string | null {
  if (ts.isPropertyAccessExpression(node)) return node.name.text.toLowerCase();
  if (ts.isElementAccessExpression(node) && node.argumentExpression)
    return propertyName(node.argumentExpression);
  return null;
}

function isEventDiscriminant(node: ts.Expression): boolean {
  const property = discriminantProperty(node);
  return Boolean(property && eventProperties.has(property));
}

function normalizedEvent(value: string): string {
  return value.trim().toLowerCase().slice(0, 300);
}

function enclosingSymbol(symbols: ProjectSymbol[], line: number): ProjectSymbol | undefined {
  return symbols
    .filter((symbol) => line >= symbol.line && line <= (symbol.endLine ?? symbol.line))
    .sort(
      (left, right) =>
        (left.endLine ?? left.line) - left.line - ((right.endLine ?? right.line) - right.line),
    )[0];
}

interface Traversal {
  symbolIds: string[];
  callEdgeIds: string[];
  truncated: boolean;
}

function traverseCalls(starts: string[], callsByCaller: Map<string, ProjectCallEdge[]>): Traversal {
  const symbols = new Set(starts);
  const edges = new Set<string>();
  const queue = starts.map((id) => ({ id, depth: 0 }));
  let truncated = false;
  for (let index = 0; index < queue.length; index++) {
    const current = queue[index]!;
    const outgoing = callsByCaller.get(current.id) ?? [];
    if (current.depth >= maximumTraversalDepth) {
      if (outgoing.some((edge) => edge.targetSymbolId)) truncated = true;
      continue;
    }
    for (const edge of outgoing) {
      if (edges.size >= maximumCallEdges) {
        truncated = true;
        break;
      }
      edges.add(edge.id);
      if (!edge.targetSymbolId || symbols.has(edge.targetSymbolId)) continue;
      if (symbols.size >= maximumReachableSymbols) {
        truncated = true;
        continue;
      }
      symbols.add(edge.targetSymbolId);
      queue.push({ id: edge.targetSymbolId, depth: current.depth + 1 });
    }
  }
  return {
    symbolIds: [...symbols].sort(),
    callEdgeIds: [...edges].sort(),
    truncated,
  };
}

function endpointCandidate(entrypoint: ProjectEntrypoint): boolean {
  if (!routeKinds.has(entrypoint.kind)) return false;
  const label = `${entrypoint.route ?? ''}/${entrypoint.file}/${entrypoint.name}`;
  return webhookPattern.test(label) || callbackPattern.test(label);
}

function directOrReachableFacts(
  entrypoint: ProjectEntrypoint,
  traversal: Traversal,
  facts: ProjectFact[],
): ProjectFact[] {
  const symbols = new Set(traversal.symbolIds);
  return facts.filter(
    (fact) =>
      fact.file === entrypoint.file ||
      Boolean(fact.ownerSymbolId && symbols.has(fact.ownerSymbolId)),
  );
}

function eventReferences(
  snapshot: Snapshot,
  profile: ProjectProfile,
  reachableSymbolIds: Set<string>,
): { references: WebhookEventReference[]; parseFailures: number; truncated: boolean } {
  const references: WebhookEventReference[] = [];
  const seen = new Set<string>();
  const symbolsByFile = new Map<string, ProjectSymbol[]>();
  for (const symbol of profile.symbols) {
    const existing = symbolsByFile.get(symbol.file) ?? [];
    existing.push(symbol);
    symbolsByFile.set(symbol.file, existing);
  }
  let parseFailures = 0;
  let truncated = false;

  const add = (
    sourceFile: SourceFile,
    source: ts.SourceFile,
    node: ts.Node,
    value: string,
    direction: WebhookEventReference['direction'],
    origin: WebhookEventReference['origin'],
    symbol: ProjectSymbol | undefined,
  ) => {
    const normalized = normalizedEvent(value);
    if (!normalized || normalized.length > 300 || references.length >= maximumEventReferences) {
      if (references.length >= maximumEventReferences) truncated = true;
      return;
    }
    const line = lineOf(source, node);
    const key = `${sourceFile.path}:${line}:${direction}:${origin}:${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    references.push({
      id: `webhook-event-${stableId(key)}`,
      file: sourceFile.path,
      line,
      event: value.slice(0, 300),
      normalizedEvent: normalized,
      direction,
      origin,
      ...(symbol ? { symbolId: symbol.id } : {}),
      ...(symbol?.componentId ? { componentId: symbol.componentId } : {}),
    });
  };

  for (const file of snapshot.files) {
    if (file.scope !== 'runtime' || !sourcePattern.test(file.path)) continue;
    const fileSymbols = symbolsByFile.get(file.path) ?? [];
    const hasReachableSymbol = fileSymbols.some((symbol) => reachableSymbolIds.has(symbol.id));
    if (!hasReachableSymbol && !dispatchPattern.test(file.content)) continue;
    const source = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
      .parseDiagnostics;
    if (diagnostics?.length) {
      parseFailures++;
      continue;
    }
    const visit = (node: ts.Node): void => {
      if (references.length >= maximumEventReferences) {
        truncated = true;
        return;
      }
      const line = lineOf(source, node);
      const symbol = enclosingSymbol(fileSymbols, line);
      const reachable = Boolean(symbol && reachableSymbolIds.has(symbol.id));
      if (reachable && ts.isCaseClause(node)) {
        const switchStatement = node.parent.parent;
        const value = stringValue(node.expression);
        if (
          ts.isSwitchStatement(switchStatement) &&
          isEventDiscriminant(switchStatement.expression) &&
          value
        )
          add(file, source, node.expression, value, 'consumed', 'branch', symbol);
      }
      if (reachable && ts.isBinaryExpression(node)) {
        const equality = new Set([
          ts.SyntaxKind.EqualsEqualsToken,
          ts.SyntaxKind.EqualsEqualsEqualsToken,
          ts.SyntaxKind.ExclamationEqualsToken,
          ts.SyntaxKind.ExclamationEqualsEqualsToken,
        ]).has(node.operatorToken.kind);
        if (equality) {
          const left = stringValue(node.left);
          const right = stringValue(node.right);
          if (left && isEventDiscriminant(node.right))
            add(file, source, node.left, left, 'consumed', 'branch', symbol);
          if (right && isEventDiscriminant(node.left))
            add(file, source, node.right, right, 'consumed', 'branch', symbol);
        }
      }
      if (ts.isPropertyAssignment(node) && eventProperties.has(propertyName(node.name) ?? '')) {
        const value = stringValue(node.initializer);
        if (value && reachable && ts.isObjectLiteralExpression(node.parent)) {
          let parent: ts.Node = node.parent;
          while (
            ts.isParenthesizedExpression(parent.parent) ||
            ts.isAsExpression(parent.parent) ||
            ts.isSatisfiesExpression(parent.parent)
          )
            parent = parent.parent;
          if (ts.isReturnStatement(parent.parent))
            add(file, source, node.initializer, value, 'produced', 'return-contract', symbol);
        }
        if (value && ts.isObjectLiteralExpression(node.parent)) {
          let parent: ts.Node = node.parent;
          while (
            parent.parent &&
            !ts.isCallExpression(parent.parent) &&
            !ts.isSourceFile(parent.parent)
          )
            parent = parent.parent;
          if (ts.isCallExpression(parent.parent)) {
            const call = parent.parent;
            const callee = call.expression.getText(source).slice(0, 300);
            if (dispatchPattern.test(callee))
              add(file, source, node.initializer, value, 'produced', 'dispatch-call', symbol);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }

  return { references, parseFailures, truncated };
}

export function scanWebhookContract(
  snapshot: Snapshot,
  profile: ProjectProfile,
): { analysis: WebhookContractAnalysis; run: ScannerRun } {
  const started = performance.now();
  const callsByCaller = new Map<string, ProjectCallEdge[]>();
  for (const call of profile.calls) {
    if (!call.callerSymbolId) continue;
    const existing = callsByCaller.get(call.callerSymbolId) ?? [];
    existing.push(call);
    callsByCaller.set(call.callerSymbolId, existing);
  }
  const candidates = profile.entrypoints.filter(endpointCandidate);
  const candidateTraversals = candidates.map((entrypoint) => ({
    entrypoint,
    traversal: traverseCalls(entrypoint.symbolIds, callsByCaller),
  }));
  const selected = candidateTraversals
    .filter(({ entrypoint, traversal }) => {
      const label = `${entrypoint.route ?? ''}/${entrypoint.file}/${entrypoint.name}`;
      return (
        webhookPattern.test(label) ||
        directOrReachableFacts(entrypoint, traversal, profile.facts).some(
          (fact) => fact.kind === 'webhook-verification',
        )
      );
    })
    .slice(0, maximumEndpoints);
  const reachableSymbolIds = new Set(selected.flatMap(({ traversal }) => traversal.symbolIds));
  const extracted = eventReferences(snapshot, profile, reachableSymbolIds);
  const endpoints: WebhookEndpointContract[] = selected.map(({ entrypoint, traversal }) => {
    const facts = directOrReachableFacts(entrypoint, traversal, profile.facts);
    const symbols = new Set(traversal.symbolIds);
    const relatedEvents = extracted.references.filter(
      (reference) => reference.symbolId && symbols.has(reference.symbolId),
    );
    const verificationEvidenceIds = facts
      .filter((fact) => fact.kind === 'webhook-verification')
      .map((fact) => fact.id)
      .sort();
    const idempotencyEvidenceIds = facts
      .filter((fact) => fact.kind === 'idempotency')
      .map((fact) => fact.id)
      .sort();
    return {
      id: `webhook-endpoint-${stableId(entrypoint.id)}`,
      entrypointId: entrypoint.id,
      file: entrypoint.file,
      line: entrypoint.line,
      ...(entrypoint.route ? { route: entrypoint.route } : {}),
      methods: [...entrypoint.methods].sort(),
      ...(entrypoint.componentId ? { componentId: entrypoint.componentId } : {}),
      reachableSymbolIds: traversal.symbolIds,
      callEdgeIds: traversal.callEdgeIds,
      verificationEvidenceIds,
      idempotencyEvidenceIds,
      eventReferenceIds: relatedEvents.map((reference) => reference.id).sort(),
      verification: verificationEvidenceIds.length ? 'evidenced' : 'unverified',
      idempotency: idempotencyEvidenceIds.length ? 'evidenced' : 'unverified',
      traversalTruncated: traversal.truncated,
    };
  });

  const eventsByName = new Map<string, WebhookEventReference[]>();
  for (const reference of extracted.references) {
    const existing = eventsByName.get(reference.normalizedEvent) ?? [];
    existing.push(reference);
    eventsByName.set(reference.normalizedEvent, existing);
  }
  const events = [...eventsByName.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([normalized, references]) => {
      const producers = references.filter((reference) => reference.direction === 'produced');
      const consumers = references.filter((reference) => reference.direction === 'consumed');
      return {
        id: `webhook-contract-${stableId(normalized)}`,
        event: references[0]!.event,
        normalizedEvent: normalized,
        producerReferenceIds: producers.map((reference) => reference.id).sort(),
        consumerReferenceIds: consumers.map((reference) => reference.id).sort(),
        status: producers.length
          ? consumers.length
            ? ('matched-local' as const)
            : ('external-producer-boundary' as const)
          : ('external-consumer-boundary' as const),
      };
    });
  const truncated =
    snapshot.truncated ||
    profile.truncated ||
    candidates.length > maximumEndpoints ||
    selected.some(({ traversal }) => traversal.truncated) ||
    extracted.truncated;
  const status: WebhookContractAnalysis['status'] = !endpoints.length
    ? 'unsupported'
    : truncated || extracted.parseFailures || profile.status !== 'complete'
      ? 'partial'
      : 'complete';
  const analysis: WebhookContractAnalysis = {
    schemaVersion: 1,
    version: '1.0.0',
    status,
    endpoints,
    eventReferences: extracted.references,
    events,
    summary: {
      endpoints: endpoints.length,
      verifiedEndpoints: endpoints.filter((endpoint) => endpoint.verification === 'evidenced')
        .length,
      idempotentEndpoints: endpoints.filter((endpoint) => endpoint.idempotency === 'evidenced')
        .length,
      producedEvents: events.filter((event) => event.producerReferenceIds.length).length,
      consumedEvents: events.filter((event) => event.consumerReferenceIds.length).length,
      matchedEvents: events.filter((event) => event.status === 'matched-local').length,
      externalConsumerBoundaries: events.filter(
        (event) => event.status === 'external-consumer-boundary',
      ).length,
      externalProducerBoundaries: events.filter(
        (event) => event.status === 'external-producer-boundary',
      ).length,
    },
    parseFailures: extracted.parseFailures,
    truncated,
    limitations: [
      'Target TypeScript and JavaScript are parsed as inert syntax; modules, configuration, and handlers are never imported or executed.',
      'Endpoints are limited to statically mapped HTTP routes whose names contain webhook/hook, or callback routes linked to captured signature-verification evidence.',
      'Call reachability follows statically resolved project-profile call edges to a bounded depth; dynamic dispatch and generated code remain unverified.',
      'Event names come only from literal discriminant branches, literal returned contracts, and literal payloads passed to recognized dispatch-like calls.',
      'Consumer-only and producer-only names are labeled external boundaries, not defects, because the other side may live at a provider or customer endpoint.',
      'Verification and idempotency statuses report captured evidence only; unverified does not prove the runtime control is absent.',
    ],
  };
  return {
    analysis,
    run: {
      id: 'webhook-contract',
      name: 'Webhook endpoint and event contract',
      status: status === 'unsupported' ? 'skipped' : status === 'partial' ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: 0,
      detail:
        status === 'unsupported'
          ? 'No statically mapped webhook endpoint was found.'
          : `Mapped ${endpoints.length} webhook endpoint(s), ${analysis.summary.verifiedEndpoints} with verification evidence, and ${analysis.summary.matchedEvents} locally paired event contract(s).`,
      version: '1.0.0',
    },
  };
}
