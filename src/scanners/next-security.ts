import ts from 'typescript';
import type {
  Category,
  Finding,
  ProjectEntrypoint,
  ProjectFact,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import {
  callPathToFact,
  effectiveEntrypointFacts,
  isMutatingEntrypoint,
  isWebhookEntrypoint,
  sensitiveProjectFactKinds,
} from '../domain/project-graph.ts';
import { isRuntimeSource } from '../security/paths.ts';

const maximumFindings = 300;
const sourcePattern = /\.[cm]?[jt]sx?$/i;
const sensitiveResponseName =
  /^(?:accessToken|apiKey|authorization|cookie|jwt|password|privateKey|refreshToken|secret|serviceRoleKey|session|token)$/i;
const privatePublicEnvironmentName =
  /^NEXT_PUBLIC_.*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|TOKEN|API_KEY)/i;

export interface NextSecurityResult {
  findings: Finding[];
  run: ScannerRun;
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

function callName(call: ts.CallExpression): string {
  return call.expression.getText(call.getSourceFile()).replace(/\s+/g, '').slice(0, 180);
}

function propertyName(name: ts.PropertyName): string {
  return ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)
    ? name.text
    : name.getText();
}

function isFunction(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

function hasFunctionDirective(node: ts.FunctionLikeDeclaration, directive: string): boolean {
  if (!node.body || !ts.isBlock(node.body)) return false;
  for (const statement of node.body.statements) {
    if (!ts.isExpressionStatement(statement) || !ts.isStringLiteral(statement.expression)) break;
    if (statement.expression.text === directive) return true;
  }
  return false;
}

function userSpecificText(node: ts.Node): boolean {
  return /(?:\bcookies\s*\(|\bheaders\s*\(|\bauth\s*\(|get(?:Current)?(?:Session|User)\s*\(|require(?:Session|User)\s*\()/i.test(
    node.getText(node.getSourceFile()),
  );
}

function sourceFinding(input: {
  file: SourceFile;
  source: ts.SourceFile;
  node: ts.Node;
  ruleId: string;
  title: string;
  category: Category;
  severity: 'high' | 'medium';
  description: string;
  remediation: string;
  cwe: string[];
  observation: string;
}): Finding {
  const evidence = sourceEvidence(input.file, lineOf(input.source, input.node), input.observation);
  evidence.kind = 'inferred';
  return makeFinding({
    source: 'next',
    ruleId: input.ruleId,
    title: input.title,
    category: input.category,
    severity: input.severity,
    sourceSeverity: input.severity.toUpperCase(),
    description: input.description,
    remediation: input.remediation,
    cwe: input.cwe,
    evidence: [evidence],
  });
}

function structuralFinding(input: {
  snapshot: Snapshot;
  profile: ProjectProfile;
  entrypoint: ProjectEntrypoint;
  fact: ProjectFact;
  ruleId: string;
  title: string;
  category: Category;
  severity: 'high' | 'medium';
  description: string;
  remediation: string;
  cwe: string[];
}): Finding | null {
  const file = input.snapshot.files.find((item) => item.path === input.fact.file);
  if (!file) return null;
  const evidence = [
    sourceEvidence(
      file,
      input.fact.line,
      `${input.entrypoint.name} ${input.entrypoint.route ?? input.entrypoint.file} reaches ${input.fact.signal}.`,
    ),
  ];
  evidence[0]!.kind = 'inferred';
  const boundaryFile = input.snapshot.files.find((item) => item.path === input.entrypoint.file);
  if (boundaryFile) {
    const boundary = sourceEvidence(
      boundaryFile,
      input.entrypoint.line,
      `Mapped ${input.entrypoint.kind} ${input.entrypoint.name}${input.entrypoint.route ? ` ${input.entrypoint.route}` : ''}.`,
    );
    boundary.kind = 'source';
    evidence.push(boundary);
  }
  for (const edge of callPathToFact(input.profile, input.entrypoint, input.fact)) {
    const edgeFile = input.snapshot.files.find((item) => item.path === edge.file);
    if (!edgeFile) continue;
    const step = sourceEvidence(edgeFile, edge.line, `Call path continues through ${edge.callee}.`);
    step.kind = 'inferred';
    evidence.push(step);
  }
  return makeFinding({
    source: 'next',
    ruleId: input.ruleId,
    title: input.title,
    category: input.category,
    severity: input.severity,
    sourceSeverity: input.severity.toUpperCase(),
    description: input.description,
    remediation: input.remediation,
    cwe: input.cwe,
    evidence,
  });
}

function publicReadRoute(entrypoint: ProjectEntrypoint): boolean {
  return /\/(?:auth(?:\/|$)|health(?:z)?(?:\/|$)|status(?:\/|$)|public(?:\/|$)|webhooks?(?:\/|$)|callbacks?(?:\/|$))/i.test(
    entrypoint.route ?? '',
  );
}

function isStateChangingFact(fact: ProjectFact): boolean {
  if (fact.kind === 'billing' || fact.kind === 'raw-sql' || fact.kind === 'command-execution')
    return true;
  if (fact.kind === 'file-access')
    return /(?:write|append|unlink|rename|createwritestream)/i.test(fact.signal);
  return (
    fact.kind === 'database' &&
    /(?:^|\.)(?:create|update|upsert|delete|executeraw|transaction)$/i.test(fact.signal)
  );
}

function structuralFindings(snapshot: Snapshot, profile: ProjectProfile): Finding[] {
  const findings: Finding[] = [];
  for (const entrypoint of profile.entrypoints) {
    if (entrypoint.kind === 'middleware' || isWebhookEntrypoint(entrypoint)) continue;
    const facts = effectiveEntrypointFacts(profile, entrypoint);
    const sensitive = facts.find((fact) => sensitiveProjectFactKinds.has(fact.kind));
    if (!sensitive) continue;
    const authenticated = facts.some((fact) =>
      ['authentication', 'authorization'].includes(fact.kind),
    );
    const authorized = facts.some((fact) => fact.kind === 'authorization');
    const scoped = facts.some((fact) => fact.kind === 'resource-scope');
    const validated = facts.some((fact) => fact.kind === 'validation');
    const read = entrypoint.methods.some((method) => ['GET', 'HEAD'].includes(method));

    if (read && !authenticated && !publicReadRoute(entrypoint)) {
      const candidate = structuralFinding({
        snapshot,
        profile,
        entrypoint,
        fact: sensitive,
        ruleId: 'TW-NEXT001',
        title: 'Sensitive read route has no mapped authentication guard',
        category: 'authentication',
        severity: 'medium',
        description:
          'A Next.js read route reaches a sensitive source operation without recognized authentication in the route, applicable middleware, or five explicit call hops. Public intent and external controls remain unverified.',
        remediation:
          'Require an authenticated principal before reading private data, or explicitly document and test that the route is public and returns only approved fields.',
        cwe: ['CWE-306', 'CWE-862'],
      });
      if (candidate) findings.push(candidate);
    }

    if (
      read &&
      entrypoint.dynamicParameters.length > 0 &&
      facts.some((fact) => fact.kind === 'database') &&
      !scoped &&
      !authorized
    ) {
      const database = facts.find((fact) => fact.kind === 'database')!;
      const candidate = structuralFinding({
        snapshot,
        profile,
        entrypoint,
        fact: database,
        ruleId: 'TW-NEXT002',
        title: 'Dynamic read route has no mapped tenant or owner scope',
        category: 'authorization',
        severity: 'high',
        description:
          'A caller-selectable Next.js route parameter reaches a database read without a recognized tenant, owner, account, organization, user, or policy decision.',
        remediation:
          'Bind the lookup to the authenticated principal or tenant and add cross-tenant and wrong-owner read tests.',
        cwe: ['CWE-639', 'CWE-862'],
      });
      if (candidate) findings.push(candidate);
    }

    const stateChanging = facts.find(isStateChangingFact);
    if (isMutatingEntrypoint(entrypoint) && stateChanging && !validated) {
      const candidate = structuralFinding({
        snapshot,
        profile,
        entrypoint,
        fact: stateChanging,
        ruleId: 'TW-NEXT006',
        title: 'Sensitive mutation has no mapped input validation',
        category: 'configuration',
        severity: 'medium',
        description:
          'A Next.js mutation reaches a sensitive operation without a recognized schema or validation call in five explicit call hops.',
        remediation:
          'Validate and bound caller-controlled input at the server boundary with a maintained schema before authorization-sensitive or state-changing operations.',
        cwe: ['CWE-20'],
      });
      if (candidate) findings.push(candidate);
    }
    if (findings.length >= maximumFindings) break;
  }
  return findings;
}

function environmentName(node: ts.Node, source: ts.SourceFile): string | undefined {
  if (ts.isPropertyAccessExpression(node) && node.expression.getText(source) === 'process.env')
    return node.name.text;
  if (
    ts.isElementAccessExpression(node) &&
    node.expression.getText(source) === 'process.env' &&
    node.argumentExpression &&
    ts.isStringLiteralLike(node.argumentExpression)
  )
    return node.argumentExpression.text;
  return undefined;
}

function sensitiveResponseProperty(call: ts.CallExpression): ts.PropertyAssignment | undefined {
  if (!/(?:^|\.)(?:json|send)$/.test(callName(call))) return;
  const payload = call.arguments[0];
  if (!payload || !ts.isObjectLiteralExpression(payload)) return;
  return payload.properties.find(
    (property): property is ts.PropertyAssignment =>
      ts.isPropertyAssignment(property) && sensitiveResponseName.test(propertyName(property.name)),
  );
}

function directFindings(snapshot: Snapshot, profile: ProjectProfile): Finding[] {
  const findings: Finding[] = [];
  const nextFiles = new Set(
    profile.entrypoints
      .filter((entrypoint) =>
        ['next-route', 'next-pages-api', 'server-action'].includes(entrypoint.kind),
      )
      .map((entrypoint) => entrypoint.file),
  );
  for (const file of snapshot.files.filter(
    (item) => isRuntimeSource(item) && sourcePattern.test(item.path),
  )) {
    const source = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    let publicCacheReported = false;
    const routeFacts = profile.entrypoints
      .filter((entrypoint) => entrypoint.file === file.path)
      .flatMap((entrypoint) => effectiveEntrypointFacts(profile, entrypoint));
    const authenticatedRoute = routeFacts.some((fact) =>
      ['authentication', 'authorization'].includes(fact.kind),
    );

    const visit = (node: ts.Node): void => {
      if (findings.length >= maximumFindings) return;
      const name = environmentName(node, source);
      if (name && privatePublicEnvironmentName.test(name))
        findings.push(
          sourceFinding({
            file,
            source,
            node,
            ruleId: 'TW-NEXT004',
            title: 'Sensitive-shaped configuration is declared public',
            category: 'secrets',
            severity: 'high',
            description:
              'A NEXT_PUBLIC environment name contains a credential- or secret-shaped marker. Next.js can inline public variables into browser bundles.',
            remediation:
              'Remove privileged values from NEXT_PUBLIC variables, rotate any exposed credential, and inspect built assets and deployment history.',
            cwe: ['CWE-200', 'CWE-798'],
            observation: `${name} is eligible for client bundle inlining.`,
          }),
        );

      if (isFunction(node) && hasFunctionDirective(node, 'use cache') && userSpecificText(node))
        findings.push(
          sourceFinding({
            file,
            source,
            node,
            ruleId: 'TW-NEXT003',
            title: 'User-specific request state is used inside a cached function',
            category: 'authorization',
            severity: 'high',
            description:
              'A function marked use cache reads request- or session-specific state. Shared cache entries can mix data across users when identity is not an explicit cache key.',
            remediation:
              'Read request state outside the cached function and pass a minimal stable tenant/user key only when caching private data is explicitly designed and isolated.',
            cwe: ['CWE-524'],
            observation: 'use cache function reads request- or session-specific state.',
          }),
        );

      if (ts.isCallExpression(node)) {
        if (/(?:^|\.)unstable_cache$/.test(callName(node))) {
          const callback = node.arguments[0];
          if (
            callback &&
            (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) &&
            callback.parameters.length === 0 &&
            userSpecificText(callback)
          )
            findings.push(
              sourceFinding({
                file,
                source,
                node,
                ruleId: 'TW-NEXT003',
                title: 'User-specific request state is used inside a cached function',
                category: 'authorization',
                severity: 'high',
                description:
                  'A zero-argument unstable_cache callback reads request- or session-specific state without an explicit identity cache key.',
                remediation:
                  'Keep request APIs outside unstable_cache and include an explicit non-secret tenant/user key only when private caching is necessary and isolated.',
                cwe: ['CWE-524'],
                observation:
                  'unstable_cache callback reads user-specific state without parameters.',
              }),
            );
        }

        const responseProperty = nextFiles.has(file.path)
          ? sensitiveResponseProperty(node)
          : undefined;
        if (responseProperty)
          findings.push(
            sourceFinding({
              file,
              source,
              node: responseProperty,
              ruleId: 'TW-NEXT007',
              title: 'Sensitive-shaped value is returned from a server boundary',
              category: 'secrets',
              severity: 'high',
              description:
                'A Next.js route or action response includes a credential-, token-, cookie-, password-, secret-, or session-shaped property. The value reaches the client response boundary.',
              remediation:
                'Return only minimal non-sensitive fields. Keep credentials and privileged session objects server-side and rotate any value that was exposed.',
              cwe: ['CWE-200'],
              observation: `${propertyName(responseProperty.name)} is included in a server response object.`,
            }),
          );

        if (
          !publicCacheReported &&
          authenticatedRoute &&
          /(?:s-maxage|public|max-age)\s*=|\bpublic\b/i.test(node.getText(source)) &&
          /cache-control/i.test(node.getText(source))
        ) {
          publicCacheReported = true;
          findings.push(
            sourceFinding({
              file,
              source,
              node,
              ruleId: 'TW-NEXT005',
              title: 'Authenticated response declares shared HTTP caching',
              category: 'authorization',
              severity: 'high',
              description:
                'A Next.js boundary with mapped authentication declares public or shared cache semantics. Personalized responses may be reused across users or tenants.',
              remediation:
                'Use private/no-store for personalized responses, or prove that the cached representation is public and varies safely on every relevant identity dimension.',
              cwe: ['CWE-524'],
              observation: 'Authenticated route declares a public or shared Cache-Control policy.',
            }),
          );
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return findings;
}

export function scanNextSecurity(snapshot: Snapshot, profile: ProjectProfile): NextSecurityResult {
  const started = performance.now();
  const next = profile.frameworks.some((framework) => framework.id.startsWith('nextjs'));
  if (!next)
    return {
      findings: [],
      run: {
        id: 'next-security',
        name: 'Next.js application security',
        status: 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail:
          'No supported Next.js framework signal was mapped. No clean Next.js result is implied.',
        version: '0.2.0',
      },
    };

  const findings = [...structuralFindings(snapshot, profile), ...directFindings(snapshot, profile)];
  const limited = findings.slice(0, maximumFindings);
  const partial =
    profile.status === 'partial' || snapshot.truncated || findings.length > maximumFindings;
  return {
    findings: limited,
    run: {
      id: 'next-security',
      name: 'Next.js application security',
      status: partial ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: limited.length,
      detail: `Evaluated ${profile.entrypoints.length} mapped entry point(s) for authenticated reads, object scope, input validation, user-specific caching, public environment exposure, and sensitive response fields.${partial ? ' Structural coverage was partial.' : ''}`,
      version: '0.2.0',
    },
  };
}
