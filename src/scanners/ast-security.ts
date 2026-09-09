import type {
  Finding,
  ProjectEntrypoint,
  ProjectFact,
  ProjectProfile,
  ScannerRun,
  Snapshot,
} from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';

const mutatingMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const sensitiveKinds = new Set<ProjectFact['kind']>([
  'database',
  'raw-sql',
  'command-execution',
  'file-access',
]);

export interface AstSecurityResult {
  findings: Finding[];
  run: ScannerRun;
}

function rootsForEntrypoint(profile: ProjectProfile, entrypoint: ProjectEntrypoint): string[] {
  if (entrypoint.kind !== 'next-route') return entrypoint.symbolIds;
  return entrypoint.symbolIds.filter((id) => {
    const symbol = profile.symbols.find((item) => item.id === id);
    return symbol ? mutatingMethods.has(symbol.name) : false;
  });
}

function isMutating(entrypoint: ProjectEntrypoint): boolean {
  if (entrypoint.kind === 'server-action') return true;
  return entrypoint.methods.some((method) => mutatingMethods.has(method));
}

function reachableSymbols(profile: ProjectProfile, roots: string[], maximumDepth = 2): Set<string> {
  const visited = new Set(roots);
  let frontier = [...roots];
  for (let depth = 0; depth < maximumDepth && frontier.length; depth++) {
    const next: string[] = [];
    for (const edge of profile.calls) {
      if (!edge.callerSymbolId || !edge.targetSymbolId || !frontier.includes(edge.callerSymbolId))
        continue;
      if (!visited.has(edge.targetSymbolId)) {
        visited.add(edge.targetSymbolId);
        next.push(edge.targetSymbolId);
      }
    }
    frontier = next;
  }
  return visited;
}

function factsFor(profile: ProjectProfile, symbols: Set<string>): ProjectFact[] {
  return profile.facts.filter((fact) => fact.ownerSymbolId && symbols.has(fact.ownerSymbolId));
}

function evidence(
  snapshot: Snapshot,
  fact: ProjectFact,
  entrypoint: ProjectEntrypoint,
  observation: string,
) {
  const file = snapshot.files.find((item) => item.path === fact.file);
  if (!file) return [];
  const primary = sourceEvidence(file, fact.line, observation);
  primary.kind = 'inferred';
  if (entrypoint.file === fact.file && entrypoint.line === fact.line) return [primary];
  const boundaryFile = snapshot.files.find((item) => item.path === entrypoint.file);
  if (!boundaryFile) return [primary];
  const boundary = sourceEvidence(
    boundaryFile,
    entrypoint.line,
    `Mapped ${entrypoint.kind} boundary${entrypoint.route ? ` ${entrypoint.route}` : ''}.`,
  );
  boundary.kind = 'source';
  return [primary, boundary];
}

function finding(input: {
  snapshot: Snapshot;
  entrypoint: ProjectEntrypoint;
  fact: ProjectFact;
  ruleId: string;
  title: string;
  description: string;
  remediation: string;
  cwe: string[];
}): Finding | null {
  const observation = `${input.entrypoint.kind} ${input.entrypoint.route ?? input.entrypoint.name} reaches ${input.fact.signal} within the bounded structural call map.`;
  const mappedEvidence = evidence(input.snapshot, input.fact, input.entrypoint, observation);
  if (!mappedEvidence.length) return null;
  return makeFinding({
    source: 'ast',
    ruleId: input.ruleId,
    title: input.title,
    category: 'authorization',
    severity: 'high',
    sourceSeverity: 'HIGH',
    description: input.description,
    remediation: input.remediation,
    cwe: input.cwe,
    evidence: mappedEvidence,
  });
}

export function scanAstSecurity(snapshot: Snapshot, profile: ProjectProfile): AstSecurityResult {
  const started = Date.now();
  if (profile.status === 'unsupported')
    return {
      findings: [],
      run: {
        id: 'ast-security',
        name: 'Framework-aware AST security',
        status: 'skipped',
        durationMs: Date.now() - started,
        findings: 0,
        detail:
          'No supported structural profile was available. No clean authorization result is implied.',
        version: '0.1.0',
      },
    };

  const findings: Finding[] = [];
  for (const entrypoint of profile.entrypoints) {
    if (!isMutating(entrypoint) || entrypoint.kind === 'middleware') continue;
    if (/\/(?:webhooks?|callbacks?)(?:\/|$)/i.test(entrypoint.route ?? '')) continue;
    const roots = rootsForEntrypoint(profile, entrypoint);
    if (!roots.length) continue;
    const mappedFacts = factsFor(profile, reachableSymbols(profile, roots));
    const sensitive = mappedFacts.find((fact) => sensitiveKinds.has(fact.kind));
    if (!sensitive) continue;
    const authenticated = mappedFacts.some((fact) =>
      ['authentication', 'authorization'].includes(fact.kind),
    );
    if (!authenticated) {
      const candidate = finding({
        snapshot,
        entrypoint,
        fact: sensitive,
        ruleId: 'TW-AST001',
        title: 'Sensitive mutation has no mapped authentication guard',
        description:
          'The structural profile connects a mutating entry point to a sensitive operation but found no recognized authentication or authorization fact in the entry point or two explicit call hops. Middleware, an API gateway, database policy, or an unrecognized wrapper may still protect it.',
        remediation:
          'Require an authenticated principal at a trusted server boundary, enforce authorization close to the operation, and add an unauthenticated regression test. Confirm any external control before dispositioning this candidate.',
        cwe: ['CWE-306', 'CWE-862'],
      });
      if (candidate) findings.push(candidate);
    }
    const administrative = /(?:^|\/)(?:admin|internal)(?:\/|$)/i.test(
      `${entrypoint.route ?? ''}/${entrypoint.file}`,
    );
    const authorized = mappedFacts.some((fact) => fact.kind === 'authorization');
    if (administrative && !authorized) {
      const candidate = finding({
        snapshot,
        entrypoint,
        fact: sensitive,
        ruleId: 'TW-AST002',
        title: 'Administrative mutation has no mapped permission check',
        description:
          'A privileged-looking entry point reaches a sensitive operation, but the bounded structural map found no recognized role, permission, or policy decision. Authentication alone would not establish administrative authorization.',
        remediation:
          'Enforce an explicit server-side permission decision for this administrative action and test an authenticated non-admin principal. Record external policy evidence during human review if it is enforced elsewhere.',
        cwe: ['CWE-862', 'CWE-863'],
      });
      if (candidate) findings.push(candidate);
    }
    const resourceOperation = mappedFacts.find((fact) => fact.kind === 'database');
    const scoped = mappedFacts.some((fact) => fact.kind === 'resource-scope');
    if (entrypoint.dynamicParameters.length && resourceOperation && !scoped) {
      const candidate = finding({
        snapshot,
        entrypoint,
        fact: resourceOperation,
        ruleId: 'TW-AST003',
        title: 'Dynamic resource operation has no mapped tenant or owner scope',
        description:
          'A route with caller-selectable path parameters reaches a database operation, but the captured call arguments contain no recognized tenant, owner, account, organization, or user scope. A prior policy decision, wrapper, or database RLS may still enforce object access.',
        remediation:
          'Bind the operation to the authenticated tenant or owner, or perform an explicit object-level authorization decision. Add cross-tenant and wrong-owner identifier tests.',
        cwe: ['CWE-639', 'CWE-862'],
      });
      if (candidate) findings.push(candidate);
    }
    if (findings.length >= 300) break;
  }
  const partial = profile.status === 'partial' || findings.length >= 300;
  return {
    findings: findings.slice(0, 300),
    run: {
      id: 'ast-security',
      name: 'Framework-aware AST security',
      status: partial ? 'partial' : 'completed',
      durationMs: Date.now() - started,
      findings: Math.min(findings.length, 300),
      detail: `Evaluated ${profile.entrypoints.length} mapped entry point(s) across explicit call relationships up to two hops. Missing runtime, middleware, RLS, and external policy evidence remains unverified.${partial ? ' Structural coverage was partial.' : ''}`,
      version: '0.1.0',
    },
  };
}
