import { digest } from './findings.ts';
import {
  callPathToFact,
  entrypointRoots,
  reachableFacts,
  sensitiveFacts,
} from './project-graph.ts';
import type {
  Evidence,
  Finding,
  ProjectCallEdge,
  ProjectEntrypoint,
  ProjectProfile,
  ProjectSymbol,
  RiskCorrelation,
  SourceRiskPath,
  SourceRiskPathStep,
} from './types.ts';

const maximumPaths = 300;
const maximumFindingsPerPath = 50;
const closedDispositions = new Set(['false_positive', 'fixed']);

function sourceLocation(file: string, line: number): string {
  return `${file}:${line}`;
}

function evidenceOwner(profile: ProjectProfile, evidence: Evidence): ProjectSymbol | undefined {
  const line = evidence.focusLine ?? evidence.startLine;
  return profile.symbols
    .filter(
      (symbol) =>
        symbol.file === evidence.file &&
        symbol.endLine !== undefined &&
        symbol.line <= line &&
        symbol.endLine >= line,
    )
    .sort(
      (left, right) =>
        left.endLine! - left.line - (right.endLine! - right.line) ||
        right.line - left.line ||
        left.id.localeCompare(right.id),
    )[0];
}

function eligibleFinding(profile: ProjectProfile, finding: Finding): boolean {
  if (closedDispositions.has(finding.disposition)) return false;
  return finding.evidence.some(
    (evidence) =>
      evidence.kind !== 'dependency' &&
      evidence.kind !== 'history' &&
      evidence.scope !== 'test' &&
      evidence.scope !== 'example' &&
      profile.symbols.some((symbol) => symbol.file === evidence.file),
  );
}

function pathSymbols(
  profile: ProjectProfile,
  entrypoint: ProjectEntrypoint,
  calls: ProjectCallEdge[],
): Set<string> {
  return new Set([
    ...entrypointRoots(profile, entrypoint),
    ...calls.flatMap((call) => [call.callerSymbolId, call.targetSymbolId]).filter(Boolean),
  ] as string[]);
}

function findingTouchesPath(
  profile: ProjectProfile,
  finding: Finding,
  symbols: Set<string>,
  locations: Set<string>,
): boolean {
  return finding.evidence.some((evidence) => {
    const line = evidence.focusLine ?? evidence.startLine;
    if (locations.has(sourceLocation(evidence.file, line))) return true;
    const owner = evidenceOwner(profile, evidence);
    return owner ? symbols.has(owner.id) : false;
  });
}

function stepsFor(
  entrypoint: ProjectEntrypoint,
  calls: ProjectCallEdge[],
  fact: ProjectProfile['facts'][number],
): SourceRiskPathStep[] {
  return [
    {
      kind: 'entrypoint',
      referenceId: entrypoint.id,
      file: entrypoint.file,
      line: entrypoint.line,
      label: entrypoint.route ?? entrypoint.name,
    },
    ...calls.map((call) => ({
      kind: 'call' as const,
      referenceId: call.id,
      file: call.file,
      line: call.line,
      label: call.callee,
    })),
    {
      kind: 'sensitive-operation',
      referenceId: fact.id,
      file: fact.file,
      line: fact.line,
      label: `${fact.kind}: ${fact.signal}`,
    },
  ];
}

function pathCandidate(
  profile: ProjectProfile,
  entrypoint: ProjectEntrypoint,
  calls: ProjectCallEdge[],
  fact: ProjectProfile['facts'][number],
  findings: Finding[],
): SourceRiskPath | undefined {
  const steps = stepsFor(entrypoint, calls, fact);
  const locations = new Set(steps.map((step) => sourceLocation(step.file, step.line)));
  const symbols = pathSymbols(profile, entrypoint, calls);
  if (fact.ownerSymbolId) symbols.add(fact.ownerSymbolId);
  const related = findings
    .filter((finding) => findingTouchesPath(profile, finding, symbols, locations))
    .sort(
      (left, right) =>
        (right.priority ?? 0) - (left.priority ?? 0) || left.id.localeCompare(right.id),
    );
  if (!related.length) return undefined;
  return {
    id: digest(
      ['source-risk-path-v1', entrypoint.id, ...calls.map((call) => call.id), fact.id].join(':'),
    ).slice(0, 24),
    entrypointId: entrypoint.id,
    ...(entrypoint.route ? { route: entrypoint.route } : {}),
    methods: entrypoint.methods,
    factId: fact.id,
    factKind: fact.kind,
    findingIds: related.slice(0, maximumFindingsPerPath).map((finding) => finding.id),
    priority: Math.max(...related.map((finding) => finding.priority ?? 0)),
    confidence: 'high',
    steps,
    truncated: related.length > maximumFindingsPerPath,
  };
}

export function buildRiskCorrelation(
  profile: ProjectProfile,
  allFindings: Finding[],
): RiskCorrelation {
  const findings = allFindings.filter((finding) => eligibleFinding(profile, finding));
  const candidates: SourceRiskPath[] = [];
  for (const entrypoint of profile.entrypoints) {
    for (const fact of sensitiveFacts(reachableFacts(profile, entrypoint))) {
      const calls = callPathToFact(profile, entrypoint, fact);
      const path = pathCandidate(profile, entrypoint, calls, fact, findings);
      if (path) candidates.push(path);
    }
  }
  candidates.sort(
    (left, right) => right.priority - left.priority || left.id.localeCompare(right.id),
  );
  const paths = candidates.slice(0, maximumPaths);
  const correlatedFindingIds = new Set(paths.flatMap((path) => path.findingIds));
  const factKinds: RiskCorrelation['summary']['factKinds'] = {};
  for (const path of paths) factKinds[path.factKind] = (factKinds[path.factKind] ?? 0) + 1;
  return {
    schemaVersion: 1,
    version: '1.0.0',
    status: profile.status,
    paths,
    summary: {
      paths: paths.length,
      entrypoints: new Set(paths.map((path) => path.entrypointId)).size,
      eligibleFindings: findings.length,
      correlatedFindings: correlatedFindingIds.size,
      uncorrelatedFindings: findings.filter((finding) => !correlatedFindingIds.has(finding.id))
        .length,
      factKinds,
    },
    truncated: candidates.length > maximumPaths || paths.some((path) => path.truncated),
    limitations: [
      'Paths contain only captured entrypoints, resolved static call edges, source symbol ranges, and sensitive-operation facts.',
      'A source path is not proof that the code executes at runtime or that the candidate is exploitable.',
      ...(profile.status === 'complete'
        ? []
        : ['Partial or unsupported project profiling limits source-path correlation.']),
    ],
  };
}
