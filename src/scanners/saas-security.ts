import ts from 'typescript';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import type {
  Category,
  Finding,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';
import { isRuntimeSource } from '../security/paths.ts';
import { defaultSaasConfiguration } from './declarative-config.ts';

const sourcePattern = /\.[cm]?[jt]sx?$/i;
const maximumFindings = 300;
const maximumNodesPerFile = 200_000;
const requestNames = new Set(['request', 'req', 'input', 'body', 'payload', 'searchParams']);

export interface SaasSecurityResult {
  findings: Finding[];
  run: ScannerRun;
}

interface ParsedSource {
  file: SourceFile;
  source: ts.SourceFile;
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

function propertyName(node: ts.PropertyName | ts.BindingName | undefined): string | null {
  if (!node) return null;
  return ts.isIdentifier(node) || ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)
    ? node.text
    : null;
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  return name.elements.flatMap((element) =>
    ts.isOmittedExpression(element) ? [] : bindingNames(element.name),
  );
}

function executableFunction(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

function functionName(node: ts.FunctionLikeDeclaration): string | null {
  if (ts.isFunctionDeclaration(node)) return node.name?.text ?? null;
  if (ts.isMethodDeclaration(node)) return propertyName(node.name);
  if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    ts.isVariableDeclaration(node.parent)
  )
    return propertyName(node.parent.name);
  if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    ts.isCallExpression(node.parent)
  )
    return `callback@${lineOf(node.getSourceFile(), node)}`;
  return null;
}

function callName(call: ts.CallExpression): string {
  return call.expression.getText(call.getSourceFile()).replace(/\s+/g, '').slice(-220);
}

function isDirectRequestSource(node: ts.Node): boolean {
  const text = node.getText(node.getSourceFile()).replace(/\s+/g, '');
  return (
    /\b(?:request|req)\.(?:body|query|params)(?:\b|\[)/i.test(text) ||
    /\b(?:request|req)\.(?:json|formData|text)\(/i.test(text) ||
    /\b(?:searchParams|url)\.get\(/i.test(text)
  );
}

function isServerOwnedLookup(node: ts.Node): boolean {
  if (!ts.isElementAccessExpression(node)) return false;
  const base = node.expression.getText(node.getSourceFile()).replace(/\s+/g, '');
  return (
    /^[A-Z][A-Z0-9_]*$/.test(base) ||
    /(?:catalog|plans?|prices?|products?|allow(?:ed|list)|mapping|lookup)/i.test(base)
  );
}

function isTrustedIdentityResolver(node: ts.Node): boolean {
  let value = node;
  while (
    ts.isAwaitExpression(value) ||
    ts.isParenthesizedExpression(value) ||
    ts.isAsExpression(value) ||
    ts.isTypeAssertionExpression(value) ||
    ts.isNonNullExpression(value)
  )
    value = value.expression;
  if (!ts.isCallExpression(value)) return false;
  const name = callName(value).split('.').at(-1) ?? '';
  return /^(?:auth|currentUser|(?:get|resolve)[A-Za-z0-9]*(?:Access|Identity|Session|Viewer)|require[A-Za-z0-9]*(?:Access|Identity|Permission|Role|Session|User))$/i.test(
    name,
  );
}

function expressionIsTainted(node: ts.Node, tainted: Set<string>): boolean {
  if (isServerOwnedLookup(node)) return false;
  if (isTrustedIdentityResolver(node)) return false;
  if (isDirectRequestSource(node)) return true;
  let found = false;
  let inspected = 0;
  const visit = (child: ts.Node): void => {
    if (found || inspected++ > 2000) return;
    if (ts.isIdentifier(child) && tainted.has(child.text)) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

function collectTaintedNames(source: ts.Node): Set<string> {
  const tainted = new Set<string>();
  const seedParameters = (node: ts.Node): void => {
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)
    ) {
      for (const parameter of node.parameters)
        for (const name of bindingNames(parameter.name))
          if (requestNames.has(name)) tainted.add(name);
    }
    ts.forEachChild(node, seedParameters);
  };
  seedParameters(source);

  for (let pass = 0; pass < 4; pass++) {
    const visit = (node: ts.Node): void => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        if (expressionIsTainted(node.initializer, tainted))
          for (const name of bindingNames(node.name)) tainted.add(name);
      } else if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        expressionIsTainted(node.right, tainted)
      ) {
        if (ts.isIdentifier(node.left)) tainted.add(node.left.text);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return tainted;
}

function boundaryTaints(
  parsed: ParsedSource,
  profile: ProjectProfile,
): Map<ts.FunctionLikeDeclaration, Set<string>> {
  const entrypointSymbols = new Set(
    profile.entrypoints.flatMap((entrypoint) => entrypoint.symbolIds),
  );
  const locations = new Set(
    profile.symbols
      .filter((symbol) => entrypointSymbols.has(symbol.id) && symbol.file === parsed.file.path)
      .map((symbol) => `${symbol.line}:${symbol.name}`),
  );
  const taints = new Map<ts.FunctionLikeDeclaration, Set<string>>();
  const visit = (node: ts.Node): void => {
    if (executableFunction(node)) {
      const name = functionName(node);
      if (name && locations.has(`${lineOf(parsed.source, node)}:${name}`))
        taints.set(node, collectTaintedNames(node));
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed.source);
  return taints;
}

function taintForNode(
  node: ts.Node,
  taints: Map<ts.FunctionLikeDeclaration, Set<string>>,
): Set<string> | null {
  let current: ts.Node | undefined = node;
  while (current) {
    if (executableFunction(current) && taints.has(current)) return taints.get(current)!;
    current = current.parent;
  }
  return null;
}

function finding(input: {
  parsed: ParsedSource;
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
  const evidence = sourceEvidence(
    input.parsed.file,
    lineOf(input.parsed.source, input.node),
    input.observation,
  );
  evidence.kind = 'inferred';
  return makeFinding({
    source: 'saas',
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

function sensitiveProperties(
  node: ts.Node,
  names: Set<string>,
  tainted: Set<string>,
): (ts.PropertyAssignment | ts.ShorthandPropertyAssignment)[] {
  const results: (ts.PropertyAssignment | ts.ShorthandPropertyAssignment)[] = [];
  let inspected = 0;
  const visit = (child: ts.Node): void => {
    if (inspected++ > 5000) return;
    if (ts.isPropertyAssignment(child)) {
      const name = propertyName(child.name);
      if (name && names.has(name.toLowerCase()) && expressionIsTainted(child.initializer, tainted))
        results.push(child);
    } else if (ts.isShorthandPropertyAssignment(child)) {
      const name = child.name.text;
      if (names.has(name.toLowerCase()) && tainted.has(name)) results.push(child);
    }
    ts.forEachChild(child, visit);
  };
  visit(node);
  return results;
}

function objectProperties(
  node: ts.Node,
): (ts.PropertyAssignment | ts.ShorthandPropertyAssignment)[] {
  const results: (ts.PropertyAssignment | ts.ShorthandPropertyAssignment)[] = [];
  let inspected = 0;
  const visit = (child: ts.Node): void => {
    if (inspected++ > 5000) return;
    if (ts.isPropertyAssignment(child) || ts.isShorthandPropertyAssignment(child))
      results.push(child);
    ts.forEachChild(child, visit);
  };
  visit(node);
  return results;
}

function databaseMutationPayloads(call: ts.CallExpression, name: string): ts.Expression[] {
  const first = call.arguments[0];
  if (!first) return [];
  if (!ts.isObjectLiteralExpression(first)) return [first];
  const keys = /\.upsert$/i.test(name) ? new Set(['create', 'update']) : new Set(['data']);
  const payloads = first.properties.flatMap((property) => {
    if (!ts.isPropertyAssignment(property)) return [];
    const key = propertyName(property.name)?.toLowerCase();
    return key && keys.has(key) ? [property.initializer] : [];
  });
  return payloads.length ? payloads : [first];
}

function propertyInitializer(
  property: ts.PropertyAssignment | ts.ShorthandPropertyAssignment,
): ts.Expression {
  return ts.isPropertyAssignment(property) ? property.initializer : property.name;
}

function isProtectedTransform(node: ts.Node): boolean {
  return /(?:hash|digest|hmac|scrypt|argon|bcrypt|mask|redact|sanitize)\s*\(/i.test(
    node.getText(node.getSourceFile()),
  );
}

function containsSensitiveValue(node: ts.Node, sensitiveNames: Set<string>): boolean {
  if (ts.isCallExpression(node) && isProtectedTransform(node)) return false;
  let found = false;
  let inspected = 0;
  const visit = (child: ts.Node): void => {
    if (found || inspected++ > 2000) return;
    if (ts.isCallExpression(child) && isProtectedTransform(child)) return;
    if (ts.isPropertyAssignment(child)) {
      const name = propertyName(child.name);
      if (
        name &&
        sensitiveNames.has(name.toLowerCase()) &&
        !isProtectedTransform(child.initializer)
      ) {
        found = true;
        return;
      }
    }
    if (
      (ts.isIdentifier(child) || ts.isPropertyAccessExpression(child)) &&
      sensitiveNames.has((ts.isIdentifier(child) ? child.text : child.name.text).toLowerCase())
    ) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

function isBillingSink(name: string): boolean {
  return /(?:checkout\.sessions|paymentintents|subscriptions|invoiceitems|prices|refunds|transactions)\.(?:create|update|capture|cancel)$/i.test(
    name,
  );
}

function isDatabaseMutation(name: string): boolean {
  return (
    /\.(?:create|createMany|update|updateMany|upsert)$/i.test(name) &&
    /(?:prisma|database|\bdb\b|repository|model|supabase|drizzle)/i.test(name)
  );
}

function isLoggingSink(name: string): boolean {
  return /(?:^|\.)(?:console|logger|log|audit|analytics|telemetry)\.(?:log|info|warn|error|debug|trace|track|identify|capture|record)$/i.test(
    name,
  );
}

function isOauthSink(name: string): boolean {
  return /(?:oauth|openid|oidc|authorization|authorize|token).*(?:create|exchange|redirect|request|start|url)$/i.test(
    name,
  );
}

function isRecoveryTokenSink(name: string): boolean {
  return (
    /(?:password.?reset|account.?recovery|invitation?|verification).*(?:create|upsert)$/i.test(
      name,
    ) ||
    /(?:create|upsert).*(?:password.?reset|account.?recovery|invitation?|verification)/i.test(name)
  );
}

function sensitiveUrlKey(value: string, sensitiveNames: Set<string>): boolean {
  const normalized = value.replace(/[-_]/g, '').toLowerCase();
  return [...sensitiveNames].some((name) => name.replace(/[-_]/g, '').toLowerCase() === normalized);
}

function urlLeak(call: ts.CallExpression, sensitiveNames: Set<string>): boolean {
  const name = callName(call);
  if (/\.searchParams\.(?:set|append)$/i.test(name)) {
    const key = call.arguments[0];
    return Boolean(key && ts.isStringLiteralLike(key) && sensitiveUrlKey(key.text, sensitiveNames));
  }
  if (!/(?:URL|URLSearchParams|redirect)$/i.test(name)) return false;
  return call.arguments.some((argument) => {
    const text = argument.getText(argument.getSourceFile());
    return [...sensitiveNames].some(
      (sensitive) =>
        new RegExp(`[?&]${sensitive.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=`, 'i').test(text) &&
        /\$\{|\+/.test(text),
    );
  });
}

function weakEntropy(node: ts.Node): boolean {
  return /(?:Math\.random\s*\(|Date\.now\s*\(|new\s+Date\s*\(\s*\)\.getTime\s*\()/i.test(
    node.getText(node.getSourceFile()),
  );
}

function identifierIsPropertyName(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (
    (ts.isPropertyAssignment(parent) && parent.name === node) ||
    (ts.isPropertyAccessExpression(parent) && parent.name === node) ||
    (ts.isMethodDeclaration(parent) && parent.name === node) ||
    (ts.isGetAccessorDeclaration(parent) && parent.name === node) ||
    (ts.isSetAccessorDeclaration(parent) && parent.name === node)
  );
}

function staticPublicErrorValue(node: ts.Expression): boolean {
  if (ts.isStringLiteralLike(node)) return true;
  if (ts.isConditionalExpression(node))
    return staticPublicErrorValue(node.whenTrue) && staticPublicErrorValue(node.whenFalse);
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isSatisfiesExpression(node)
  )
    return staticPublicErrorValue(node.expression);
  return false;
}

function returnsOnlyStaticPublicErrors(node: ts.FunctionLikeDeclaration): boolean {
  if (!node.body) return false;
  if (!ts.isBlock(node.body)) return staticPublicErrorValue(node.body);

  let returns = 0;
  let unsafe = false;
  const visit = (child: ts.Node): void => {
    if (unsafe || (child !== node.body && executableFunction(child))) return;
    if (ts.isReturnStatement(child)) {
      returns++;
      if (!child.expression || !staticPublicErrorValue(child.expression)) unsafe = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(node.body);
  return returns > 0 && !unsafe;
}

function staticPublicErrorSymbols(parsed: ParsedSource[], profile: ProjectProfile): Set<string> {
  const symbolsByLocation = new Map(
    profile.symbols.map((symbol) => [`${symbol.file}:${symbol.line}:${symbol.name}`, symbol.id]),
  );
  const safe = new Set<string>();
  for (const item of parsed) {
    const visit = (node: ts.Node): void => {
      if (executableFunction(node) && returnsOnlyStaticPublicErrors(node)) {
        const name = functionName(node);
        if (name) {
          const symbol = symbolsByLocation.get(
            `${item.file.path}:${lineOf(item.source, node)}:${name}`,
          );
          if (symbol) safe.add(symbol);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(item.source);
  }
  return safe;
}

function resolvedCallTargets(parsed: ParsedSource, profile: ProjectProfile): Map<string, string> {
  return new Map(
    profile.calls
      .filter((call) => call.file === parsed.file.path && call.targetSymbolId)
      .map((call) => [`${call.line}:${call.callee.replace(/\s+/g, '')}`, call.targetSymbolId!]),
  );
}

function containsCaughtErrorValue(
  node: ts.Node,
  caught: Set<string>,
  parsed: ParsedSource,
  callTargets: Map<string, string>,
  staticPublicSymbols: Set<string>,
): boolean {
  let found = false;
  const visit = (child: ts.Node): void => {
    if (found) return;
    if (ts.isCallExpression(child)) {
      const target = callTargets.get(`${lineOf(parsed.source, child)}:${callName(child)}`);
      if (target && staticPublicSymbols.has(target)) return;
    }
    if (ts.isIdentifier(child) && caught.has(child.text) && !identifierIsPropertyName(child)) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

function containsCaughtErrorPayload(
  node: ts.Expression,
  caught: Set<string>,
  parsed: ParsedSource,
  callTargets: Map<string, string>,
  staticPublicSymbols: Set<string>,
): boolean {
  if (ts.isIdentifier(node)) return caught.has(node.text);
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isSatisfiesExpression(node) ||
    ts.isAwaitExpression(node)
  )
    return containsCaughtErrorPayload(
      node.expression,
      caught,
      parsed,
      callTargets,
      staticPublicSymbols,
    );
  if (ts.isConditionalExpression(node))
    return (
      containsCaughtErrorPayload(
        node.whenTrue,
        caught,
        parsed,
        callTargets,
        staticPublicSymbols,
      ) ||
      containsCaughtErrorPayload(
        node.whenFalse,
        caught,
        parsed,
        callTargets,
        staticPublicSymbols,
      )
    );
  if (ts.isBinaryExpression(node)) {
    const carriesOperand = [
      ts.SyntaxKind.AmpersandAmpersandToken,
      ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken,
      ts.SyntaxKind.PlusToken,
    ].includes(node.operatorToken.kind);
    return (
      carriesOperand &&
      (containsCaughtErrorPayload(
        node.left,
        caught,
        parsed,
        callTargets,
        staticPublicSymbols,
      ) ||
        containsCaughtErrorPayload(
          node.right,
          caught,
          parsed,
          callTargets,
          staticPublicSymbols,
        ))
    );
  }
  if (ts.isPropertyAccessExpression(node))
    return containsCaughtErrorPayload(
      node.expression,
      caught,
      parsed,
      callTargets,
      staticPublicSymbols,
    );
  if (ts.isElementAccessExpression(node))
    return containsCaughtErrorPayload(
      node.expression,
      caught,
      parsed,
      callTargets,
      staticPublicSymbols,
    );
  if (ts.isCallExpression(node)) {
    const target = callTargets.get(`${lineOf(parsed.source, node)}:${callName(node)}`);
    if (target && staticPublicSymbols.has(target)) return false;
    if (
      ts.isPropertyAccessExpression(node.expression) &&
      containsCaughtErrorPayload(
        node.expression.expression,
        caught,
        parsed,
        callTargets,
        staticPublicSymbols,
      )
    )
      return true;
    return node.arguments.some((argument) =>
      containsCaughtErrorPayload(
        argument,
        caught,
        parsed,
        callTargets,
        staticPublicSymbols,
      ),
    );
  }
  if (ts.isTemplateExpression(node))
    return node.templateSpans.some((span) =>
      containsCaughtErrorPayload(
        span.expression,
        caught,
        parsed,
        callTargets,
        staticPublicSymbols,
      ),
    );
  if (ts.isArrayLiteralExpression(node))
    return node.elements.some((element) =>
      ts.isSpreadElement(element)
        ? containsCaughtErrorPayload(
            element.expression,
            caught,
            parsed,
            callTargets,
            staticPublicSymbols,
          )
        : containsCaughtErrorPayload(
            element,
            caught,
            parsed,
            callTargets,
            staticPublicSymbols,
          ),
    );
  if (ts.isObjectLiteralExpression(node))
    return node.properties.some((property) => {
      if (ts.isPropertyAssignment(property))
        return containsCaughtErrorPayload(
          property.initializer,
          caught,
          parsed,
          callTargets,
          staticPublicSymbols,
        );
      if (ts.isShorthandPropertyAssignment(property)) return caught.has(property.name.text);
      if (ts.isSpreadAssignment(property))
        return containsCaughtErrorPayload(
          property.expression,
          caught,
          parsed,
          callTargets,
          staticPublicSymbols,
        );
      return false;
    });
  return false;
}

function collectCaughtErrorAliases(
  catchClause: ts.CatchClause,
  caught: Set<string>,
  parsed: ParsedSource,
  callTargets: Map<string, string>,
  staticPublicSymbols: Set<string>,
): void {
  for (let pass = 0; pass < 8; pass++) {
    let changed = false;
    const visit = (node: ts.Node): void => {
      if (node !== catchClause.block && executableFunction(node)) return;
      if (
        ts.isVariableDeclaration(node) &&
        node.initializer &&
        containsCaughtErrorPayload(
          node.initializer,
          caught,
          parsed,
          callTargets,
          staticPublicSymbols,
        )
      ) {
        for (const name of bindingNames(node.name)) {
          if (!caught.has(name)) {
            caught.add(name);
            changed = true;
          }
        }
      } else if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(node.left) &&
        containsCaughtErrorPayload(
          node.right,
          caught,
          parsed,
          callTargets,
          staticPublicSymbols,
        ) &&
        !caught.has(node.left.text)
      ) {
        caught.add(node.left.text);
        changed = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(catchClause.block);
    if (!changed) break;
  }
}

function caughtErrorExposure(
  catchClause: ts.CatchClause,
  parsed: ParsedSource,
  profile: ProjectProfile,
  staticPublicSymbols: Set<string>,
): ts.CallExpression[] {
  const caught = new Set(
    catchClause.variableDeclaration ? bindingNames(catchClause.variableDeclaration.name) : [],
  );
  const callTargets = resolvedCallTargets(parsed, profile);
  collectCaughtErrorAliases(catchClause, caught, parsed, callTargets, staticPublicSymbols);
  const exposed: ts.CallExpression[] = [];
  const caughtNames = [...caught];
  const isValidationBranch = (node: ts.Node): boolean => {
    let current: ts.Node | undefined = node;
    while (current && current !== catchClause.block) {
      const parent: ts.Node | undefined = current.parent;
      if (parent && ts.isIfStatement(parent) && parent.thenStatement === current) {
        const condition = parent.expression.getText(parsed.source).replace(/\s+/g, ' ');
        if (
          caughtNames.some((name) =>
            new RegExp(`\\b${name}\\s+instanceof\\s+(?:z\\.)?ZodError\\b`).test(condition),
          )
        )
          return true;
      }
      current = parent;
    }
    return false;
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const name = callName(node);
      if (
        /(?:^|\.)(?:json|send|api(?:Legacy)?Error)$/i.test(name) &&
        !isValidationBranch(node) &&
        node.arguments.some((argument) =>
          containsCaughtErrorValue(argument, caught, parsed, callTargets, staticPublicSymbols),
        )
      )
        exposed.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(catchClause.block);
  return exposed;
}

function scanFile(
  parsed: ParsedSource,
  profile: ProjectProfile,
  staticPublicSymbols: Set<string>,
): Finding[] {
  const findings: Finding[] = [];
  const taints = boundaryTaints(parsed, profile);
  const vocabulary = profile.saasSemantics?.vocabulary ?? defaultSaasConfiguration.vocabulary;
  const billingKeys = new Set(vocabulary.billingKeys.map((key) => key.toLowerCase()));
  const assignmentKeys = new Set(
    [...vocabulary.tenantKeys, ...vocabulary.ownerKeys, ...vocabulary.roleKeys].map((key) =>
      key.toLowerCase(),
    ),
  );
  const tokenKeys = new Set(vocabulary.tokenKeys.map((key) => key.toLowerCase()));
  const sensitiveDataKeys = new Set(
    [
      ...vocabulary.tokenKeys,
      'password',
      'passwordHash',
      'secret',
      'apiKey',
      'authorization',
      'cookie',
      'session',
      'email',
      'phone',
      'address',
      'ssn',
      'taxId',
      'creditCard',
      'cardNumber',
    ].map((key) => key.toLowerCase()),
  );
  const oauthRedirectKeys = new Set(
    ['redirectUri', 'redirect_uri', 'callbackUrl', 'callback_url', 'returnTo'].map((key) =>
      key.toLowerCase(),
    ),
  );
  let nodes = 0;

  const add = (candidate: Finding): void => {
    if (findings.length < maximumFindings) findings.push(candidate);
  };
  const visit = (node: ts.Node): void => {
    if (nodes++ > maximumNodesPerFile || findings.length >= maximumFindings) return;
    const tainted = taintForNode(node, taints);
    if (ts.isCallExpression(node)) {
      const name = callName(node);
      if (tainted && isBillingSink(name)) {
        for (const property of sensitiveProperties(node, billingKeys, tainted)) {
          if (ts.isPropertyAssignment(property) && isServerOwnedLookup(property.initializer))
            continue;
          add(
            finding({
              parsed,
              node: property,
              ruleId: 'TW-SAAS001',
              title: 'Billing value may be controlled by the client',
              category: 'authorization',
              severity: 'high',
              description:
                'A request-derived price, product, plan, or amount reaches a billing-provider mutation. Client input should select only a server-owned catalog entry; it should not define the charged value.',
              remediation:
                'Resolve an allowlisted product or price on the server, derive amount and currency from trusted configuration, and test tampered billing fields.',
              cwe: ['CWE-20', 'CWE-602'],
              observation: `${propertyName(property.name) ?? 'Billing field'} receives request-derived data before ${name}.`,
            }),
          );
        }
      }
      if (tainted && isDatabaseMutation(name)) {
        const mutationPayloads = databaseMutationPayloads(node, name);
        for (const property of mutationPayloads.flatMap((payload) =>
          sensitiveProperties(payload, assignmentKeys, tainted),
        ))
          add(
            finding({
              parsed,
              node: property,
              ruleId: 'TW-SAAS002',
              title: 'Ownership or privilege field may be client-assigned',
              category: 'authorization',
              severity: 'high',
              description:
                'A request-derived tenant, owner, role, or permission field reaches a database mutation. Schema validation alone does not prove the caller may choose that security boundary.',
              remediation:
                'Derive ownership and tenant fields from the authenticated server context. Allowlist privilege changes behind a separate authorization decision and test cross-tenant input.',
              cwe: ['CWE-915', 'CWE-863'],
              observation: `${propertyName(property.name) ?? 'Sensitive field'} receives request-derived data before ${name}.`,
            }),
          );

        if (isRecoveryTokenSink(name)) {
          const properties = mutationPayloads.flatMap((payload) => objectProperties(payload));
          const storedTokens = properties.filter((property) => {
            const propertyKey = propertyName(property.name);
            return propertyKey ? tokenKeys.has(propertyKey.toLowerCase()) : false;
          });
          for (const property of storedTokens) {
            const initializer = propertyInitializer(property);
            const propertyKey = propertyName(property.name) ?? 'token';
            if (!/(?:hash|digest)$/i.test(propertyKey) && !isProtectedTransform(initializer))
              add(
                finding({
                  parsed,
                  node: property,
                  ruleId: 'TW-SAAS008',
                  title: 'Recovery token may be stored in plaintext',
                  category: 'authentication',
                  severity: 'high',
                  description:
                    'A reset, recovery, invitation, or verification record stores a token-shaped value without a recognized one-way transform. Database disclosure could make unused tokens immediately reusable.',
                  remediation:
                    'Store a keyed or cryptographic hash of the token, compare hashes in constant-time where applicable, and never log or return the raw value after delivery.',
                  cwe: ['CWE-256', 'CWE-312'],
                  observation: `${propertyKey} is persisted by ${name} without a recognized hash transform.`,
                }),
              );
          }
          const hasExpiry = properties.some((property) =>
            /^(?:expiresAt|expires|expiry|validUntil)$/i.test(propertyName(property.name) ?? ''),
          );
          if (storedTokens.length && !hasExpiry)
            add(
              finding({
                parsed,
                node,
                ruleId: 'TW-SAAS009',
                title: 'Recovery token record has no mapped expiry',
                category: 'authentication',
                severity: 'medium',
                description:
                  'A reset, recovery, invitation, or verification record is created with a token-shaped field but no recognized expiry field in the same bounded mutation.',
                remediation:
                  'Persist a short expiry, reject expired records before use, consume tokens atomically once, and test replay and concurrent redemption.',
                cwe: ['CWE-613'],
                observation: `${name} persists a recovery token without a mapped expiry field.`,
              }),
            );
        }
      }

      if (tainted && isLoggingSink(name)) {
        const sensitiveArgument = node.arguments.find(
          (argument) =>
            containsSensitiveValue(argument, sensitiveDataKeys) ||
            (ts.isIdentifier(argument) &&
              requestNames.has(argument.text) &&
              tainted.has(argument.text)),
        );
        if (sensitiveArgument)
          add(
            finding({
              parsed,
              node,
              ruleId: 'TW-SAAS005',
              title: 'Sensitive data may be written to logs or analytics',
              category: 'secrets',
              severity: 'medium',
              description:
                'A token-, credential-, personal-data-, session-, or whole-request-shaped value reaches a logging, telemetry, or analytics call without a recognized mask, redaction, or hash transform.',
              remediation:
                'Log stable identifiers and event metadata only. Apply centralized structured redaction and verify exported telemetry, retention, and access controls.',
              cwe: ['CWE-532', 'CWE-359'],
              observation: `${name} receives a sensitive-shaped value without a mapped protective transform.`,
            }),
          );
      }

      if (tainted && urlLeak(node, sensitiveDataKeys))
        add(
          finding({
            parsed,
            node,
            ruleId: 'TW-SAAS006',
            title: 'Sensitive value may be placed in a URL',
            category: 'secrets',
            severity: 'high',
            description:
              'A sensitive-shaped query parameter is added to a URL. URLs can leak through browser history, referrers, proxies, access logs, screenshots, and analytics.',
            remediation:
              'Keep credentials and personal data out of URLs. Use an authorization header, secure cookie, or one-time opaque exchange code with short expiry.',
            cwe: ['CWE-598'],
            observation: `${name} adds a sensitive-shaped query parameter.`,
          }),
        );

      if (tainted && isOauthSink(name))
        for (const property of sensitiveProperties(node, oauthRedirectKeys, tainted))
          add(
            finding({
              parsed,
              node: property,
              ruleId: 'TW-SAAS007',
              title: 'OAuth redirect destination may be client-controlled',
              category: 'authentication',
              severity: 'high',
              description:
                'A request-derived redirect or callback destination reaches an OAuth/OIDC-shaped operation. Weak redirect validation can leak authorization codes or tokens.',
              remediation:
                'Resolve redirect destinations from an exact server-owned allowlist and enforce state, PKCE, and nonce as required by the flow.',
              cwe: ['CWE-601', 'CWE-346'],
              observation: `${propertyName(property.name) ?? 'OAuth redirect'} receives request-derived data before ${name}.`,
            }),
          );
    }

    if (ts.isVariableDeclaration(node) && node.initializer) {
      const name = propertyName(node.name);
      if (name && tokenKeys.has(name.toLowerCase()) && weakEntropy(node.initializer))
        add(
          finding({
            parsed,
            node,
            ruleId: 'TW-SAAS003',
            title: 'Security token uses predictable entropy',
            category: 'authentication',
            severity: 'high',
            description:
              'A token-shaped value is generated from Math.random or the current time. These values are not suitable for password reset, invitation, verification, or session secrets.',
            remediation:
              'Generate tokens with crypto.randomBytes, randomUUID, or Web Crypto; store only a hash where practical; enforce expiry and one-time use.',
            cwe: ['CWE-330', 'CWE-338'],
            observation: `${name} is generated with predictable entropy.`,
          }),
        );
    }

    if (ts.isPropertyAssignment(node)) {
      const name = propertyName(node.name);
      if (name && tokenKeys.has(name.toLowerCase()) && weakEntropy(node.initializer))
        add(
          finding({
            parsed,
            node,
            ruleId: 'TW-SAAS003',
            title: 'Security token uses predictable entropy',
            category: 'authentication',
            severity: 'high',
            description:
              'A token-shaped value is generated from Math.random or the current time. These values are not suitable for password reset, invitation, verification, or session secrets.',
            remediation:
              'Generate tokens with crypto.randomBytes, randomUUID, or Web Crypto; store only a hash where practical; enforce expiry and one-time use.',
            cwe: ['CWE-330', 'CWE-338'],
            observation: `${name} is generated with predictable entropy.`,
          }),
        );
    }

    if (tainted && ts.isCatchClause(node))
      for (const call of caughtErrorExposure(node, parsed, profile, staticPublicSymbols))
        add(
          finding({
            parsed,
            node: call,
            ruleId: 'TW-SAAS004',
            title: 'Internal error details may be returned to the client',
            category: 'configuration',
            severity: 'medium',
            description:
              'A caught error object, message, stack, or cause is passed to a JSON/send response. It may disclose database, filesystem, dependency, or implementation details.',
            remediation:
              'Return a stable public error code and generic message. Record detailed diagnostics only in protected server logs with sensitive-value redaction.',
            cwe: ['CWE-209'],
            observation: `${callName(call)} returns data from the caught error.`,
          }),
        );

    ts.forEachChild(node, visit);
  };
  visit(parsed.source);
  return findings;
}

export function scanSaasSecurity(snapshot: Snapshot, profile: ProjectProfile): SaasSecurityResult {
  const started = performance.now();
  if (profile.status === 'unsupported')
    return {
      findings: [],
      run: {
        id: 'saas-security',
        name: 'SaaS application security',
        status: 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail:
          'No supported TypeScript or JavaScript profile was available. No clean SaaS result is implied.',
        version: '0.5.1',
      },
    };

  const parsed = snapshot.files
    .filter((file) => isRuntimeSource(file) && sourcePattern.test(file.path))
    .slice(0, 2000)
    .map((file) => ({
      file,
      source: ts.createSourceFile(
        file.path,
        file.content,
        ts.ScriptTarget.Latest,
        true,
        scriptKind(file.path),
      ),
    }));
  const safeErrorSymbols = staticPublicErrorSymbols(parsed, profile);
  const findings = parsed
    .flatMap((file) => scanFile(file, profile, safeErrorSymbols))
    .slice(0, maximumFindings);
  const partial =
    profile.status === 'partial' ||
    snapshot.truncated ||
    parsed.length >= 2000 ||
    findings.length >= maximumFindings;
  return {
    findings,
    run: {
      id: 'saas-security',
      name: 'SaaS application security',
      status: partial ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: findings.length,
      detail:
        'Nine bounded TypeScript/JavaScript rules review client-controlled billing, ownership or privilege assignment, token lifecycle, internal error exposure, sensitive logging and URLs, and OAuth redirect trust. Findings are source candidates, not runtime proof.',
      version: '0.5.1',
    },
  };
}
