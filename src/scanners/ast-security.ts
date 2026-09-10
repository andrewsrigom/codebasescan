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
import { isRuntimeSource } from '../security/paths.ts';
import {
  entrypointRoots,
  callPathToFact,
  effectiveEntrypointFacts,
  isAdministrativeEntrypoint,
  isMutatingEntrypoint,
  isWebhookEntrypoint,
  sensitiveProjectFactKinds,
} from '../domain/project-graph.ts';

export interface AstSecurityResult {
  findings: Finding[];
  run: ScannerRun;
}

export function preferStructuralFindings(findings: Finding[]): Finding[] {
  const structuralLocations = new Set(
    findings.flatMap((finding) =>
      ['TW-AST004', 'TW-AST009', 'TW-NEXT004', 'TW-REACT001'].includes(finding.ruleId)
        ? finding.evidence.map((item) => `${item.file}:${item.startLine}`)
        : [],
    ),
  );
  return findings.filter(
    (finding) =>
      !(
        ['TW-001', 'TW-005', 'TW-P003'].includes(finding.ruleId) &&
        finding.evidence.some((item) => structuralLocations.has(`${item.file}:${item.startLine}`))
      ),
  );
}

function evidence(
  snapshot: Snapshot,
  profile: ProjectProfile,
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
  const callPath = callPathToFact(profile, entrypoint, fact).flatMap((edge) => {
    const edgeFile = snapshot.files.find((item) => item.path === edge.file);
    if (!edgeFile) return [];
    const step = sourceEvidence(edgeFile, edge.line, `Call path continues through ${edge.callee}.`);
    step.kind = 'inferred';
    return [step];
  });
  return [primary, boundary, ...callPath];
}

function authorizationFinding(input: {
  snapshot: Snapshot;
  profile: ProjectProfile;
  entrypoint: ProjectEntrypoint;
  fact: ProjectFact;
  ruleId: string;
  title: string;
  description: string;
  remediation: string;
  cwe: string[];
  severity: 'high' | 'medium';
}): Finding | null {
  const observation = `${input.entrypoint.kind} ${input.entrypoint.route ?? input.entrypoint.name} reaches ${input.fact.signal} within the bounded structural call map.`;
  const mappedEvidence = evidence(
    input.snapshot,
    input.profile,
    input.fact,
    input.entrypoint,
    observation,
  );
  if (!mappedEvidence.length) return null;
  return makeFinding({
    source: 'ast',
    ruleId: input.ruleId,
    title: input.title,
    category: 'authorization',
    severity: input.severity,
    sourceSeverity: input.severity.toUpperCase(),
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

function sensitiveOperationSeverity(fact: ProjectFact): 'high' | 'medium' {
  if (
    fact.kind === 'database' &&
    /\.(?:findUnique|findFirst|findMany|count|aggregate|groupBy)$/i.test(fact.signal)
  )
    return 'medium';
  return 'high';
}

function isExpectedUnauthenticatedFlow(entrypoint: ProjectEntrypoint): boolean {
  const route = entrypoint.route ?? '';
  return (
    /\/auth\/(?:forgot-password|reset-password|join|unlock-account|register|signup|sign-up|login|signin|sign-in|verify|callback)(?:\/|$)/i.test(
      route,
    ) || /^\/api\/(?:waitlist|contact|newsletter|subscribe)(?:\/submit)?\/?$/i.test(route)
  );
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

function hasServerOwnedUrlPrefix(node: ts.Expression, tainted: Set<string>): boolean {
  const isOwnedPrefix = (value: string): boolean =>
    /^\/(?!\/)/.test(value) || /^https?:\/\/[^/]+(?:\/|$)/i.test(value);
  if (ts.isStringLiteralLike(node)) return isOwnedPrefix(node.text);
  if (!ts.isTemplateExpression(node)) return !isTainted(node, tainted);
  if (isOwnedPrefix(node.head.text)) return true;
  for (const span of node.templateSpans) {
    if (isTainted(span.expression, tainted)) return false;
    if (isOwnedPrefix(span.literal.text)) return true;
  }
  return false;
}

function isServerOwnedUrl(node: ts.Expression | undefined, tainted: Set<string>): boolean {
  if (!node || !ts.isNewExpression(node) || node.expression.getText() !== 'URL') return false;
  const [destination, base] = node.arguments ?? [];
  return Boolean(destination && base && hasServerOwnedUrlPrefix(destination, tainted));
}

function isTaintedValue(node: ts.Expression, tainted: Set<string>): boolean {
  let value = node;
  while (
    ts.isAwaitExpression(value) ||
    ts.isParenthesizedExpression(value) ||
    ts.isAsExpression(value) ||
    ts.isTypeAssertionExpression(value) ||
    ts.isNonNullExpression(value)
  )
    value = value.expression;
  if (isServerOwnedUrl(value, tainted)) return false;
  if (!ts.isCallExpression(value)) return isTainted(value, tainted);

  if (ts.isPropertyAccessExpression(value.expression)) {
    const method = value.expression.name.text;
    const [pattern, replacement] = value.arguments;
    const receiver = value.expression.expression;
    if (
      method === 'replace' &&
      pattern &&
      replacement &&
      receiver.getText().endsWith('.href') &&
      pattern.getText() === receiver.getText().replace(/\.href$/, '.origin') &&
      isTainted(receiver, tainted) &&
      !isTainted(replacement, tainted)
    )
      return false;
    if (
      method === 'replace' &&
      pattern &&
      replacement &&
      ['/[^a-z0-9-]/g', '/[^a-z0-9_-]/g'].includes(pattern.getText()) &&
      ts.isStringLiteralLike(replacement) &&
      replacement.text === ''
    )
      return false;
    if (
      /^(?:get|json|formData|text|arrayBuffer|toString|toLowerCase|toUpperCase|trim|slice|substring|substr|replace|replaceAll|concat)$/i.test(
        method,
      )
    )
      return isTainted(value.expression.expression, tainted);
  }
  if (/^(?:String|decodeURIComponent|encodeURIComponent|JSON\.parse)$/i.test(callName(value)))
    return value.arguments.some((argument) => isTainted(argument, tainted));
  return false;
}

function functionTaint(
  node: ts.FunctionLikeDeclarationBase,
  taintedParameterIndexes?: Set<number>,
): Set<string> {
  const tainted = new Set(
    node.parameters.flatMap((parameter, index) =>
      !taintedParameterIndexes || taintedParameterIndexes.has(index)
        ? bindingNames(parameter.name)
        : [],
    ),
  );
  // Bounded local propagation catches common request -> local -> sink flows without typechecking target code.
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    const visit = (child: ts.Node): void => {
      if (child !== node && isExecutableFunction(child)) return;
      if (
        ts.isVariableDeclaration(child) &&
        child.initializer &&
        isTaintedValue(child.initializer, tainted)
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
        isTaintedValue(child.right, tainted) &&
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

function requestBodyAccess(
  node: ts.FunctionLikeDeclarationBase,
  tainted: Set<string>,
): ts.PropertyAccessExpression | undefined {
  let found: ts.PropertyAccessExpression | undefined;
  const visit = (child: ts.Node): void => {
    if (found || (child !== node && isExecutableFunction(child))) return;
    if (
      ts.isPropertyAccessExpression(child) &&
      child.name.text === 'body' &&
      isTainted(child.expression, tainted)
    ) {
      found = child;
      return;
    }
    ts.forEachChild(child, visit);
  };
  if (node.body) visit(node.body);
  return found;
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

function containsWholeTaintedObject(node: ts.Expression, tainted: Set<string>): boolean {
  let value = node;
  while (
    ts.isParenthesizedExpression(value) ||
    ts.isAsExpression(value) ||
    ts.isTypeAssertionExpression(value) ||
    ts.isNonNullExpression(value)
  )
    value = value.expression;
  if (ts.isIdentifier(value)) return tainted.has(value.text);
  if (!ts.isObjectLiteralExpression(value)) return false;
  return value.properties.some((property) => {
    if (ts.isSpreadAssignment(property))
      return ts.isIdentifier(property.expression) && tainted.has(property.expression.text);
    if (!ts.isPropertyAssignment(property)) return false;
    return containsWholeTaintedObject(property.initializer, tainted);
  });
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
  if (
    input.entrypoint &&
    (input.entrypoint.file !== input.file || input.entrypoint.line !== input.line)
  ) {
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

  for (const file of snapshot.files.filter(
    (item) => isRuntimeSource(item) && /\.[cm]?[jt]sx?$/.test(item.path),
  )) {
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
          node.name.text !== 'NODE_ENV' &&
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
            destination &&
            isTaintedValue(destination, tainted)
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
          const taintedArgument = call.arguments.find((argument) =>
            isTaintedValue(argument, tainted),
          );
          const commandOptions = localObject(node, call.arguments.at(-1));
          const shellEnabled =
            propertyValue(commandOptions ?? ts.factory.createObjectLiteralExpression(), 'shell')
              ?.kind === ts.SyntaxKind.TrueKeyword;
          const commandSink = /(?:^|\.)(?:exec|execSync)$/i.test(callee);
          const processSink = /(?:^|\.)(?:spawn|spawnSync|execFile|execFileSync)$/i.test(callee);
          if (
            taintedArgument &&
            ((commandSink && call.arguments[0] === taintedArgument) ||
              (processSink && (call.arguments[0] === taintedArgument || shellEnabled))) &&
            !hasPriorGuard(
              calls,
              call,
              /(?:allowlistedCommand|assertSafeCommand|validateCommand|safeExecutable)/i,
            )
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST011',
              title: 'Request-derived data reaches process execution',
              category: 'injection',
              severity: 'high',
              description:
                'A mapped entry point passes locally tracked request data into a command, executable name, or shell-enabled process API. The source-only analysis does not execute the command.',
              remediation:
                'Remove shell construction, select executables from a server-owned allowlist, pass fixed argument arrays, reject option-like input, and add command-injection regression tests.',
              cwe: ['CWE-78'],
              observation: `${callee} receives locally tracked request-derived data in a command-sensitive position.`,
            });
            if (candidate) findings.push(candidate);
          }
          if (
            /(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rename|renameSync|open|openSync)$/i.test(
              callee,
            ) &&
            destination &&
            isTaintedValue(destination, tainted) &&
            !hasPriorGuard(
              calls,
              call,
              /(?:basename|resolveWithin|assertSafePath|validatePath|safeFilename|sanitizeFilename)/i,
            )
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST012',
              title: 'Request-derived path reaches filesystem access',
              category: 'injection',
              severity: 'high',
              description:
                'A mapped entry point passes locally tracked request data to a filesystem path argument without a recognized containment or filename guard.',
              remediation:
                'Resolve the path beneath a server-owned root, reject absolute and parent-traversal segments after decoding, use generated filenames where possible, and test encoded traversal payloads.',
              cwe: ['CWE-22', 'CWE-23'],
              observation: `${callee} receives a request-derived path without a mapped containment guard.`,
            });
            if (candidate) findings.push(candidate);
          }
          if (
            /(?:^|\.)(?:unserialize|unserializeSync)$/i.test(callee) &&
            destination &&
            isTaintedValue(destination, tainted)
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST014',
              title: 'Request-derived data reaches unsafe object deserialization',
              category: 'injection',
              severity: 'high',
              description:
                'A mapped entry point passes request-derived data into an unserialize API that may reconstruct executable or prototype-bearing objects.',
              remediation:
                'Use a data-only format and validate the parsed shape against an allowlisted schema. Do not deserialize executable object graphs from untrusted input.',
              cwe: ['CWE-502'],
              observation: `${callee} receives locally tracked request-derived data.`,
            });
            if (candidate) findings.push(candidate);
          }
          const weakAlgorithm = call.arguments[0];
          if (
            /(?:^|\.)(?:createHash|createHmac)$/i.test(callee) &&
            weakAlgorithm &&
            ts.isStringLiteralLike(weakAlgorithm) &&
            /^(?:md4|md5|sha1)$/i.test(weakAlgorithm.text)
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST015',
              title: 'Security-sensitive flow uses a weak digest algorithm',
              category: 'configuration',
              severity: 'medium',
              description: `${callee} selects ${weakAlgorithm.text}. Weak digests may still be acceptable for non-security checksums, so the purpose requires review.`,
              remediation:
                'Use a modern construction appropriate to the purpose: SHA-256 or stronger for integrity, HMAC for authentication, and scrypt/Argon2/bcrypt for password storage.',
              cwe: ['CWE-327', 'CWE-328'],
              observation: `${callee} explicitly selects ${weakAlgorithm.text}.`,
            });
            if (candidate) findings.push(candidate);
          }
          if (
            /(?:^|\.)(?:create|update|upsert|insert)$/i.test(callee) &&
            /(?:prisma|database|db|repository|model|client|supabase|drizzle)/i.test(callee) &&
            call.arguments.some((argument) => containsWholeTaintedObject(argument, tainted)) &&
            !hasPriorGuard(calls, call, /(?:parse|safeParse|validate|validateAsync|isValid)$/i)
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST018',
              title: 'Request object reaches a data mutation without mapped schema validation',
              category: 'authorization',
              severity: 'medium',
              description:
                'A mapped entry point passes a locally tracked request object into a data mutation without a prior recognized schema-validation call. Field selection performed in a wrapper may not be visible.',
              remediation:
                'Parse an allowlisted mutation DTO, map only permitted fields, bind tenant/owner identifiers server-side, and test attempts to set privileged properties.',
              cwe: ['CWE-915'],
              observation: `${callee} receives request-derived mutation data without a mapped validation call.`,
            });
            if (candidate) findings.push(candidate);
          }
          if (
            /(?:mongo|mongoose|collection|repository|db).*(?:find|findOne|aggregate|deleteOne|updateOne)$/i.test(
              callee,
            ) &&
            destination &&
            containsWholeTaintedObject(destination, tainted) &&
            !hasPriorGuard(calls, call, /(?:parse|safeParse|validate|validateAsync|isValid)$/i)
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: sinkLine,
              entrypoint,
              ruleId: 'TW-AST017',
              title: 'Request object reaches a NoSQL query without mapped schema validation',
              category: 'injection',
              severity: 'high',
              description:
                'A mapped entry point passes a whole request-derived object to a NoSQL-shaped query API. Operator keys may change query semantics when sanitization is absent.',
              remediation:
                'Parse an exact query DTO, construct the database filter from allowlisted scalar fields, reject operator-prefixed keys, and test nested operator payloads.',
              cwe: ['CWE-943'],
              observation: `${callee} receives a whole locally tracked request-derived query object.`,
            });
            if (candidate) findings.push(candidate);
          }
          if (
            /^(?:fetch|axios(?:\.request|\.get|\.post)?|got(?:\.get|\.post)?)$/i.test(callee) &&
            destination &&
            isTaintedValue(destination, tainted) &&
            !isServerOwnedUrl(destination, tainted) &&
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
            destination &&
            isTaintedValue(destination, tainted) &&
            !isServerOwnedUrl(destination, tainted) &&
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

        const visitDynamicSinks = (child: ts.Node): void => {
          if (child !== node && isExecutableFunction(child)) return;
          if (
            ts.isNewExpression(child) &&
            child.expression.getText(source) === 'RegExp' &&
            child.arguments?.[0] &&
            isTaintedValue(child.arguments[0], tainted)
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: lineOf(source, child),
              entrypoint,
              ruleId: 'TW-AST013',
              title: 'Request-derived pattern is compiled as a regular expression',
              category: 'injection',
              severity: 'medium',
              description:
                'A mapped entry point compiles request-derived text as a regular expression. Crafted patterns can cause excessive backtracking or change matching semantics.',
              remediation:
                'Use literal matching or escape metacharacters. If regex input is required, enforce a small grammar and length limit and use a safe-regex strategy.',
              cwe: ['CWE-1333', 'CWE-400'],
              observation: 'The RegExp constructor receives locally tracked request-derived data.',
            });
            if (candidate) findings.push(candidate);
          }
          if (
            ts.isBinaryExpression(child) &&
            child.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
            ts.isElementAccessExpression(child.left) &&
            child.left.argumentExpression &&
            isTaintedValue(child.left.argumentExpression, tainted)
          ) {
            const candidate = directFinding({
              snapshot,
              file: file.path,
              line: lineOf(source, child),
              entrypoint,
              ruleId: 'TW-AST016',
              title: 'Request-derived key controls a dynamic property write',
              category: 'injection',
              severity: 'high',
              description:
                'A mapped entry point uses request-derived data as the key of a dynamic object assignment. Prototype keys or privileged fields may alter object behavior.',
              remediation:
                'Map accepted keys through an exact allowlist, reject __proto__/prototype/constructor, and store arbitrary dictionaries in null-prototype objects or Map.',
              cwe: ['CWE-1321', 'CWE-915'],
              observation: 'A computed assignment key is locally tracked as request-derived.',
            });
            if (candidate) findings.push(candidate);
          }
          ts.forEachChild(child, visitDynamicSinks);
        };
        if (node.body) visitDynamicSinks(node.body);

        const bodyParse = calls.find(
          (call) => call.arguments.length === 0 && /\.(?:json|formData)$/i.test(callName(call)),
        );
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
          /(?:^|\.)(?:writeFile|createWriteStream|upload|put)$/i.test(callName(call)),
        );
        const multipart = calls.find((call) => /\.formData$/i.test(callName(call)));
        const streamedBody = requestBodyAccess(node, tainted);
        const uploadGuard = calls.some(
          (call) =>
            /(?:validateUpload|assertFile|checkFile|safeFilename|sanitizePath|basename|mime|fileSize)/i.test(
              callName(call),
            ) ||
            (/(?:file|upload)[A-Za-z0-9_]*\.(?:parse|safeParse)$/i.test(callName(call)) &&
              call.arguments.some((argument) => isTainted(argument, tainted))),
        );
        if ((multipart || streamedBody) && uploadSink && !uploadGuard) {
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
              'A mapped handler reads multipart or direct request-body data and reaches a file or upload sink without a recognized size, type, or path validation call in the same function.',
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

interface ParsedFunction {
  file: string;
  source: ts.SourceFile;
  node: ExecutableFunction;
}

function parsedFunctions(snapshot: Snapshot, profile: ProjectProfile): Map<string, ParsedFunction> {
  const symbols = new Map(
    profile.symbols.map((symbol) => [`${symbol.file}:${symbol.line}:${symbol.name}`, symbol]),
  );
  const functions = new Map<string, ParsedFunction>();
  for (const file of snapshot.files.filter(
    (item) => isRuntimeSource(item) && /\.[cm]?[jt]sx?$/.test(item.path),
  )) {
    const source = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    const visit = (node: ts.Node): void => {
      if (isExecutableFunction(node)) {
        const name = functionName(node);
        const line = lineOf(source, node);
        const symbol = name ? symbols.get(`${file.path}:${line}:${name}`) : undefined;
        if (symbol) functions.set(symbol.id, { file: file.path, source, node });
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return functions;
}

function crossFileTaintFindings(snapshot: Snapshot, profile: ProjectProfile): Finding[] {
  const findings: Finding[] = [];
  const functions = parsedFunctions(snapshot, profile);
  const edges = new Map<string, typeof profile.calls>();
  for (const edge of profile.calls) {
    if (!edge.callerSymbolId || !edge.targetSymbolId) continue;
    edges.set(edge.callerSymbolId, [...(edges.get(edge.callerSymbolId) ?? []), edge]);
  }

  for (const entrypoint of profile.entrypoints) {
    const queue = entrypointRoots(profile, entrypoint).flatMap((symbolId) => {
      const parsed = functions.get(symbolId);
      return parsed
        ? [
            {
              symbolId,
              depth: 0,
              taintedParameters: new Set(parsed.node.parameters.map((_, index) => index)),
            },
          ]
        : [];
    });
    const visited = new Set<string>();
    let inspected = 0;
    while (queue.length && inspected++ < 1_000 && findings.length < 300) {
      const current = queue.shift()!;
      if (current.depth > 5) continue;
      const key = `${current.symbolId}:${[...current.taintedParameters].sort().join(',')}`;
      if (visited.has(key)) continue;
      visited.add(key);
      const parsed = functions.get(current.symbolId);
      if (!parsed) continue;
      const tainted = functionTaint(parsed.node, current.taintedParameters);
      const calls = callsIn(parsed.node);

      if (current.depth > 0)
        for (const call of calls) {
          const callee = callName(call);
          const destination = call.arguments[0];
          const sinkLine = lineOf(parsed.source, call);
          const add = (input: {
            ruleId: string;
            title: string;
            category: Category;
            severity: 'high' | 'medium';
            description: string;
            remediation: string;
            cwe: string[];
            observation: string;
          }) => {
            const finding = directFinding({
              snapshot,
              file: parsed.file,
              line: sinkLine,
              entrypoint,
              ...input,
            });
            if (finding) findings.push(finding);
          };
          if (
            destination &&
            isTaintedValue(destination, tainted) &&
            /(?:\$queryRawUnsafe|\$executeRawUnsafe|\.raw|\.queryRaw)$/i.test(callee)
          )
            add({
              ruleId: 'TW-AST004',
              title: 'Request-derived data reaches raw SQL across a call boundary',
              category: 'injection',
              severity: 'high',
              description:
                'The bounded call map propagates a request-derived argument into an unsafe raw SQL API in another function. Runtime reachability and exploitability remain unverified.',
              remediation:
                'Use parameterized query APIs and add a regression test that reaches this helper through the mapped entry point.',
              cwe: ['CWE-89'],
              observation: `${callee} receives request-derived data after ${current.depth} mapped call hop(s).`,
            });
          if (
            destination &&
            isTaintedValue(destination, tainted) &&
            /^(?:fetch|axios(?:\.request|\.get|\.post)?|got(?:\.get|\.post)?)$/i.test(callee) &&
            !isServerOwnedUrl(destination, tainted) &&
            !hasPriorGuard(
              calls,
              call,
              /(?:allowlisted|isallowed|validatedestination|safedestination|assertsafeurl)/i,
            )
          )
            add({
              ruleId: 'TW-AST005',
              title: 'Request-derived destination reaches an outbound request across calls',
              category: 'configuration',
              severity: 'high',
              description:
                'The bounded call map propagates request-derived data into an outbound destination in another function without a recognized safety guard.',
              remediation:
                'Resolve destinations from a server-owned allowlist, reject private address ranges after DNS resolution, and validate redirects.',
              cwe: ['CWE-918'],
              observation: `${callee} receives a request-derived destination after ${current.depth} mapped call hop(s).`,
            });
          if (
            destination &&
            isTaintedValue(destination, tainted) &&
            /(?:^|\.)(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)$/i.test(callee) &&
            !hasPriorGuard(
              calls,
              call,
              /(?:allowlistedCommand|assertSafeCommand|validateCommand|safeExecutable)/i,
            )
          )
            add({
              ruleId: 'TW-AST011',
              title: 'Request-derived data reaches process execution across calls',
              category: 'injection',
              severity: 'high',
              description:
                'The bounded call map propagates a request-derived argument into a process execution API in another function.',
              remediation:
                'Use a fixed executable and argument schema without a shell, then test the complete mapped entry-point path.',
              cwe: ['CWE-78'],
              observation: `${callee} receives request-derived data after ${current.depth} mapped call hop(s).`,
            });
          if (
            destination &&
            isTaintedValue(destination, tainted) &&
            /(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rename|renameSync|open|openSync)$/i.test(
              callee,
            ) &&
            !hasPriorGuard(
              calls,
              call,
              /(?:basename|resolveWithin|assertSafePath|validatePath|safeFilename|sanitizeFilename)/i,
            )
          )
            add({
              ruleId: 'TW-AST012',
              title: 'Request-derived path reaches filesystem access across calls',
              category: 'injection',
              severity: 'high',
              description:
                'The bounded call map propagates a request-derived path into filesystem access in another function without a recognized containment guard.',
              remediation:
                'Resolve beneath a server-owned root, reject traversal after decoding, and test the complete mapped entry-point path.',
              cwe: ['CWE-22', 'CWE-23'],
              observation: `${callee} receives a request-derived path after ${current.depth} mapped call hop(s).`,
            });
        }

      for (const call of calls) {
        const edge = (edges.get(current.symbolId) ?? []).find(
          (candidate) =>
            candidate.targetSymbolId &&
            candidate.line === lineOf(parsed.source, call) &&
            candidate.callee.replace(/\s+/g, '') === callName(call),
        );
        if (!edge?.targetSymbolId) continue;
        const nextTaint = new Set<number>();
        call.arguments.forEach((argument, index) => {
          if (isTaintedValue(argument, tainted)) nextTaint.add(index);
        });
        if (nextTaint.size)
          queue.push({
            symbolId: edge.targetSymbolId,
            depth: current.depth + 1,
            taintedParameters: nextTaint,
          });
      }
    }
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
        version: '0.4.0',
      },
    };

  const findings: Finding[] = [];
  for (const entrypoint of profile.entrypoints) {
    if (!isMutatingEntrypoint(entrypoint) || entrypoint.kind === 'middleware') continue;
    if (isWebhookEntrypoint(entrypoint)) continue;
    const roots = entrypointRoots(profile, entrypoint);
    if (!roots.length) continue;
    const mappedFacts = effectiveEntrypointFacts(profile, entrypoint);
    const sensitive = mappedFacts.find((fact) => sensitiveProjectFactKinds.has(fact.kind));
    if (!sensitive) continue;
    const authenticated = mappedFacts.some((fact) =>
      ['authentication', 'authorization'].includes(fact.kind),
    );
    if (!authenticated && !isExpectedUnauthenticatedFlow(entrypoint)) {
      const candidate = authorizationFinding({
        snapshot,
        profile,
        entrypoint,
        fact: sensitive,
        ruleId: 'TW-AST001',
        title: 'Sensitive operation has no mapped authentication guard',
        severity: sensitiveOperationSeverity(sensitive),
        description:
          'The structural profile connects a mutating entry point to a sensitive operation but found no recognized authentication or authorization fact in the entry point, applicable middleware, or five explicit call hops. An API gateway, database policy, or an unrecognized wrapper may still protect it.',
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
        profile,
        entrypoint,
        fact: sensitive,
        ruleId: 'TW-AST002',
        title: 'Administrative mutation has no mapped permission check',
        severity: 'high',
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
    if (entrypoint.dynamicParameters.length && resourceOperation && !scoped && !authorized) {
      const candidate = authorizationFinding({
        snapshot,
        profile,
        entrypoint,
        fact: resourceOperation,
        ruleId: 'TW-AST003',
        title: 'Dynamic resource operation has no mapped tenant or owner scope',
        severity: 'high',
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
  findings.push(...crossFileTaintFindings(snapshot, profile));
  const partial = profile.status === 'partial' || findings.length >= 300;
  return {
    findings: findings.slice(0, 300),
    run: {
      id: 'ast-security',
      name: 'Framework-aware AST security',
      status: partial ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: Math.min(findings.length, 300),
      detail: `Evaluated ${profile.entrypoints.length} mapped entry point(s), request-data flows, SQL/NoSQL, process, filesystem, outbound, deserialization, regex, object-write, upload, cookie, and client/server boundaries. Cross-file authorization and selected taint flows follow explicit call relationships up to five hops and include applicable Next.js middleware. Missing runtime, RLS, and external policy evidence remains unverified.${partial ? ' Structural coverage was partial.' : ''}`,
      version: '0.4.0',
    },
  };
}
