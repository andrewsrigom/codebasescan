import ts from 'typescript';
import type {
  Category,
  Finding,
  ProjectEntrypoint,
  ProjectFact,
  ProjectProfile,
  ScannerRun,
  Snapshot,
} from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import {
  entrypointRoots,
  isAdministrativeEntrypoint,
  isMutatingEntrypoint,
  isWebhookEntrypoint,
  reachableFacts,
  sensitiveProjectFactKinds,
} from '../domain/project-graph.ts';

export interface AstSecurityResult {
  findings: Finding[];
  run: ScannerRun;
}

export function preferStructuralFindings(findings: Finding[]): Finding[] {
  const structuralLocations = new Set(
    findings.flatMap((finding) =>
      ['TW-AST004', 'TW-AST009'].includes(finding.ruleId)
        ? finding.evidence.map((item) => `${item.file}:${item.startLine}`)
        : [],
    ),
  );
  return findings.filter(
    (finding) =>
      !(
        ['TW-001', 'TW-P003'].includes(finding.ruleId) &&
        finding.evidence.some((item) => structuralLocations.has(`${item.file}:${item.startLine}`))
      ),
  );
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

function authorizationFinding(input: {
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

function callName(node: ts.CallExpression): string {
  return node.expression.getText().replace(/\s+/g, '').slice(0, 180);
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  return name.elements.flatMap((element) =>
    ts.isOmittedExpression(element) ? [] : bindingNames(element.name),
  );
}

type ExecutableFunction =
  ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;

function isExecutableFunction(node: ts.Node): node is ExecutableFunction {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

function isTainted(node: ts.Node | undefined, tainted: Set<string>): boolean {
  if (!node) return false;
  if (ts.isIdentifier(node)) return tainted.has(node.text);
  let found = false;
  const visit = (child: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(child) && tainted.has(child.text)) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

function functionTaint(node: ts.FunctionLikeDeclarationBase): Set<string> {
  const tainted = new Set(node.parameters.flatMap((parameter) => bindingNames(parameter.name)));
  // Bounded local propagation catches common request -> local -> sink flows without typechecking target code.
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    const visit = (child: ts.Node): void => {
      if (child !== node && isExecutableFunction(child)) return;
      if (
        ts.isVariableDeclaration(child) &&
        child.initializer &&
        isTainted(child.initializer, tainted)
      )
        for (const name of bindingNames(child.name))
          if (!tainted.has(name)) {
            tainted.add(name);
            changed = true;
          }
      if (
        ts.isBinaryExpression(child) &&
        child.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(child.left) &&
        isTainted(child.right, tainted) &&
        !tainted.has(child.left.text)
      ) {
        tainted.add(child.left.text);
        changed = true;
      }
      ts.forEachChild(child, visit);
    };
    if (node.body) visit(node.body);
    if (!changed) break;
  }
  return tainted;
}

function callsIn(node: ts.FunctionLikeDeclarationBase): ts.CallExpression[] {
  const calls: ts.CallExpression[] = [];
  const visit = (child: ts.Node): void => {
    if (child !== node && isExecutableFunction(child)) return;
    if (ts.isCallExpression(child)) calls.push(child);
    ts.forEachChild(child, visit);
  };
  if (node.body) visit(node.body);
  return calls.sort((left, right) => left.getStart() - right.getStart());
}

function propertyValue(
  object: ts.ObjectLiteralExpression,
  name: string,
): ts.Expression | undefined {
  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const key =
      ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)
        ? property.name.text
        : '';
    if (key.toLowerCase() === name.toLowerCase()) return property.initializer;
  }
  return undefined;
}

function localObject(
  node: ts.FunctionLikeDeclarationBase,
  expression: ts.Expression | undefined,
): ts.ObjectLiteralExpression | undefined {
  if (!expression) return undefined;
  if (ts.isObjectLiteralExpression(expression)) return expression;
  if (!ts.isIdentifier(expression)) return undefined;
  let found: ts.ObjectLiteralExpression | undefined;
  const visit = (child: ts.Node): void => {
    if (found || (child !== node && isExecutableFunction(child))) return;
    if (
      ts.isVariableDeclaration(child) &&
      ts.isIdentifier(child.name) &&
      child.name.text === expression.text &&
      child.initializer &&
      ts.isObjectLiteralExpression(child.initializer)
    )
      found = child.initializer;
    ts.forEachChild(child, visit);
  };
  if (node.body) visit(node.body);
  return found;
}

function hasPriorGuard(
  calls: ts.CallExpression[],
  sink: ts.CallExpression,
  pattern: RegExp,
): boolean {
  return calls.some((call) => call.getStart() < sink.getStart() && pattern.test(callName(call)));
}

function directFinding(input: {
  snapshot: Snapshot;
  file: string;
  line: number;
  entrypoint?: ProjectEntrypoint;
  ruleId: string;
  title: string;
  category: Category;
  severity: 'high' | 'medium';
  description: string;
  remediation: string;
  cwe: string[];
  observation: string;
}): Finding | null {
  const file = input.snapshot.files.find((item) => item.path === input.file);
  if (!file) return null;
  const primary = sourceEvidence(file, input.line, input.observation);
  primary.kind = 'inferred';
  const evidence = [primary];
  if (input.entrypoint && input.entrypoint.line !== input.line) {
    const boundaryFile = input.snapshot.files.find((item) => item.path === input.entrypoint!.file);
    if (boundaryFile) {
      const boundary = sourceEvidence(
        boundaryFile,
        input.entrypoint.line,
        `Mapped ${input.entrypoint.kind} boundary${input.entrypoint.route ? ` ${input.entrypoint.route}` : ''}.`,
      );
      boundary.kind = 'source';
      evidence.push(boundary);
    }
  }
  return makeFinding({
    source: 'ast',
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

function functionName(node: ts.FunctionLikeDeclarationBase): string | null {
  if (ts.isFunctionDeclaration(node)) return node.name?.text ?? null;
  if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) return node.name.text;
  if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    ts.isVariableDeclaration(node.parent) &&
    ts.isIdentifier(node.parent.name)
  )
    return node.parent.name.text;
  if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    ts.isCallExpression(node.parent)
  )
    return `callback@${lineOf(node.getSourceFile(), node)}`;
  return null;
}

function directAstFindings(snapshot: Snapshot, profile: ProjectProfile): Finding[] {
  const findings: Finding[] = [];
  const symbolsByLocation = new Map(
    profile.symbols.map((symbol) => [`${symbol.file}:${symbol.line}:${symbol.name}`, symbol]),
  );
  const entrypointsBySymbol = new Map<string, ProjectEntrypoint[]>();
  for (const entrypoint of profile.entrypoints)
    for (const symbolId of entrypoint.symbolIds)
      entrypointsBySymbol.set(symbolId, [...(entrypointsBySymbol.get(symbolId) ?? []), entrypoint]);

  for (const file of snapshot.files.filter((item) => /\.[cm]?[jt]sx?$/.test(item.path))) {
    const source = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    const clientModule = source.statements.some(
      (statement) =>
        ts.isExpressionStatement(statement) &&
        ts.isStringLiteral(statement.expression) &&
        statement.expression.text === 'use client',
    );
    if (clientModule) {
      const visitSecret = (node: ts.Node): void => {
        if (
          ts.isPropertyAccessExpression(node) &&
          node.expression.getText(source) === 'process.env' &&
          !node.name.text.startsWith('NEXT_PUBLIC_')
        ) {
          const candidate = directFinding({
            snapshot,
            file: file.path,
            line: lineOf(source, node),
            ruleId: 'TW-AST010',
            title: 'Client module references server-only environment configuration',
            category: 'secrets',
            severity: 'high',
            description:
              'A client-marked module directly references a non-public environment name. Build tooling behavior varies, so actual bundle exposure is unverified, but the server/client boundary is ambiguous.',
            remediation:
              'Move privileged configuration and all dependent logic into a server-only module. Expose only a minimal non-sensitive result to the client and inspect the production bundle.',
            cwe: ['CWE-200'],
            observation: `Client module reads process.env.${node.name.text}.`,
          });
          if (candidate) findings.push(candidate);
        }
        ts.forEachChild(node, visitSecret);
      };
      visitSecret(source);
    }

    const visitFunction = (node: ts.Node): void => {
      if (!isExecutableFunction(node) || !node.body) {
        ts.forEachChild(node, visitFunction);
        return;
      }
      const name = functionName(node);
      const line = lineOf(source, node);
      const symbol = name ? symbolsByLocation.get(`${file.path}:${line}:${name}`) : undefined;
      const entrypoints = symbol ? (entrypointsBySymbol.get(symbol.id) ?? []) : [];
      if (!entrypoints.length) {
        ts.forEachChild(node, visitFunction);
        return;
      }
      const tainted = functionTaint(node);
      const calls = callsIn(node);
      for (const entrypoint of entrypoints) {
        for (const call of calls) {
          const callee = callName(call);
          const sinkLine = lineOf(source, call);
          const destination = call.arguments[0];
          if (
            /(?:\$queryRawUnsafe|\$executeRawUnsafe|\.raw|\.queryRaw)$/i.test(callee) &&
            isTainted(destination, tainted)
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST004',
              title: 'Request-derived data reaches raw SQL construction',
              category: 'injection',
              severity: 'high',
              description:
                'Within a mapped entry point, local data derived from a handler parameter reaches an unsafe raw SQL API. The bounded analysis does not prove runtime reachability or successful injection.',
              remediation:
                'Use a parameterized query API and allowlist any unavoidable identifier fragments. Add a regression test using SQL metacharacters in the relevant request input.',
              cwe: ['CWE-89'],
              observation: `${callee} receives locally tracked request-derived data.`,
            });
            if (candidate) findings.push(candidate);
          }
          if (
            /^(?:fetch|axios(?:\.request|\.get|\.post)?|got(?:\.get|\.post)?)$/i.test(callee) &&
            isTainted(destination, tainted) &&
            !hasPriorGuard(
              calls,
              call,
              /(?:allowlisted|isallowed|validatedestination|safedestination|assertsafeurl)/i,
            )
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST005',
              title: 'Request-derived destination reaches an outbound request',
              category: 'configuration',
              severity: 'high',
              description:
                'A mapped entry point passes locally tracked request-derived data to an outbound request API without a recognized destination allowlist or URL safety guard.',
              remediation:
                'Resolve destinations from a server-owned allowlist, reject private and metadata address ranges after DNS resolution, validate every redirect, and add SSRF regression tests.',
              cwe: ['CWE-918'],
              observation: `${callee} receives a request-derived destination without a mapped safety guard.`,
            });
            if (candidate) findings.push(candidate);
          }
          if (
            /(?:^|\.)(?:redirect|permanentRedirect)$/i.test(callee) &&
            isTainted(destination, tainted) &&
            !hasPriorGuard(
              calls,
              call,
              /(?:isallowedredirect|saferedirect|validateredirect|assertsameorigin)/i,
            )
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST006',
              title: 'Request-derived destination reaches a redirect',
              category: 'configuration',
              severity: 'medium',
              description:
                'A mapped entry point redirects to locally tracked request-derived data without a recognized same-origin or destination allowlist decision.',
              remediation:
                'Accept a server-owned route key or enforce an exact same-origin/allowlist policy. Test scheme-relative, encoded, and external destinations.',
              cwe: ['CWE-601'],
              observation: `${callee} receives a request-derived redirect destination.`,
            });
            if (candidate) findings.push(candidate);
          }
        }

        const bodyParse = calls.find((call) => /\.(?:json|formData)$/i.test(callName(call)));
        const verification = calls.find((call) =>
          /(?:verifywebhook|verifysignature|constructevent|verifyhmac|checksignature)/i.test(
            callName(call),
          ),
        );
        if (
          isWebhookEntrypoint(entrypoint) &&
          bodyParse &&
          (!verification || bodyParse.getStart() < verification.getStart())
        ) {
          const candidate = directFinding({
            snapshot,
            file: file.path,
            line: lineOf(source, bodyParse),
            entrypoint,
            ruleId: 'TW-AST008',
            title: 'Webhook body is parsed before signature verification',
            category: 'authentication',
            severity: 'high',
            description:
              'A webhook-like entry point parses structured body data before a recognized signature verification call, or no verification call was mapped. Some frameworks or gateways may verify outside this handler.',
            remediation:
              'Verify the provider signature against the exact raw request bytes before parsing or acting on the payload. Reject stale/replayed events and add invalid-signature tests.',
            cwe: ['CWE-345'],
            observation: 'Structured webhook body parsing precedes mapped signature verification.',
          });
          if (candidate) findings.push(candidate);
        }

        const uploadSink = calls.find((call) =>
          /(?:writeFile|createWriteStream|\.upload|\.put)$/i.test(callName(call)),
        );
        const multipart = calls.find((call) => /\.formData$/i.test(callName(call)));
        const uploadGuard = calls.some((call) =>
          /(?:validateUpload|assertFile|checkFile|safeFilename|sanitizePath|basename|mime|fileSize)/i.test(
            callName(call),
          ),
        );
        if (multipart && uploadSink && !uploadGuard) {
          const candidate = directFinding({
            snapshot,
            file: file.path,
            line: lineOf(source, uploadSink),
            entrypoint,
            ruleId: 'TW-AST007',
            title: 'Upload reaches storage without mapped file constraints',
            category: 'configuration',
            severity: 'high',
            description:
              'A mapped handler reads multipart form data and reaches a file or upload sink without a recognized size, type, or path validation call in the same function.',
            remediation:
              'Enforce byte, MIME/content, extension, count, and server-owned path limits before storage. Use generated filenames and add oversized, polyglot, and traversal tests.',
            cwe: ['CWE-434', 'CWE-22'],
            observation: `${callName(uploadSink)} follows multipart input without mapped upload validation.`,
          });
          if (candidate) findings.push(candidate);
        }

        for (const cookieCall of calls.filter((call) =>
          /(?:cookies\(\)|\.cookies)\.set$|(?:^|\.)(?:cookie)$/i.test(callName(call)),
        )) {
          const nameArgument = cookieCall.arguments[0];
          if (!nameArgument || !ts.isStringLiteralLike(nameArgument)) continue;
          if (!/(?:session|auth|token|jwt|sid)/i.test(nameArgument.text)) continue;
          const options = localObject(node, cookieCall.arguments[2]);
          const secure = options ? propertyValue(options, 'secure') : undefined;
          const httpOnly = options ? propertyValue(options, 'httpOnly') : undefined;
          const sameSite = options ? propertyValue(options, 'sameSite') : undefined;
          const complete =
            secure?.kind === ts.SyntaxKind.TrueKeyword &&
            httpOnly?.kind === ts.SyntaxKind.TrueKeyword &&
            Boolean(sameSite);
          if (complete) continue;
          const candidate = directFinding({
            snapshot,
            file: file.path,
            line: lineOf(source, cookieCall),
            entrypoint,
            ruleId: 'TW-AST009',
            title: 'Sensitive cookie lacks explicit secure attributes',
            category: 'authentication',
            severity: 'medium',
            description:
              'A session- or token-like cookie is set without an effective local options object containing Secure, HttpOnly, and SameSite. Runtime defaults or a wrapper may still add attributes.',
            remediation:
              'Set Secure and HttpOnly explicitly, choose a suitable SameSite policy, scope Path/Domain narrowly, and verify the emitted Set-Cookie header.',
            cwe: ['CWE-614', 'CWE-1004'],
            observation: `Cookie ${nameArgument.text} is set without all recognized secure attributes.`,
          });
          if (candidate) findings.push(candidate);
        }
      }
      ts.forEachChild(node, visitFunction);
    };
    visitFunction(source);
    if (findings.length >= 300) break;
  }
  return findings.slice(0, 300);
}

export function scanAstSecurity(snapshot: Snapshot, profile: ProjectProfile): AstSecurityResult {
  const started = performance.now();
  if (profile.status === 'unsupported')
    return {
      findings: [],
      run: {
        id: 'ast-security',
        name: 'Framework-aware AST security',
        status: 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail:
          'No supported structural profile was available. No clean authorization result is implied.',
        version: '0.1.0',
      },
    };

  const findings: Finding[] = [];
  for (const entrypoint of profile.entrypoints) {
    if (!isMutatingEntrypoint(entrypoint) || entrypoint.kind === 'middleware') continue;
    if (isWebhookEntrypoint(entrypoint)) continue;
    const roots = entrypointRoots(profile, entrypoint);
    if (!roots.length) continue;
    const mappedFacts = reachableFacts(profile, entrypoint);
    const sensitive = mappedFacts.find((fact) => sensitiveProjectFactKinds.has(fact.kind));
    if (!sensitive) continue;
    const authenticated = mappedFacts.some((fact) =>
      ['authentication', 'authorization'].includes(fact.kind),
    );
    if (!authenticated) {
      const candidate = authorizationFinding({
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
    const administrative = isAdministrativeEntrypoint(entrypoint);
    const authorized = mappedFacts.some((fact) => fact.kind === 'authorization');
    if (administrative && !authorized) {
      const candidate = authorizationFinding({
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
      const candidate = authorizationFinding({
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
  findings.push(...directAstFindings(snapshot, profile));
  const partial = profile.status === 'partial' || findings.length >= 300;
  return {
    findings: findings.slice(0, 300),
    run: {
      id: 'ast-security',
      name: 'Framework-aware AST security',
      status: partial ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: Math.min(findings.length, 300),
      detail: `Evaluated ${profile.entrypoints.length} mapped entry point(s), direct request-data flows, webhook ordering, upload guards, cookie options, and client/server configuration boundaries. Cross-file authorization follows explicit call relationships up to two hops. Missing runtime, middleware, RLS, and external policy evidence remains unverified.${partial ? ' Structural coverage was partial.' : ''}`,
      version: '0.2.0',
    },
  };
}
