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

function expressionIsTainted(node: ts.Node, tainted: Set<string>): boolean {
  if (isServerOwnedLookup(node)) return false;
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

function collectTaintedNames(source: ts.SourceFile): Set<string> {
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

function isBillingSink(name: string): boolean {
  return /(?:checkout\.sessions|paymentintents|subscriptions|invoiceitems|prices)\.(?:create|update)$/i.test(
    name,
  );
}

function isDatabaseMutation(name: string): boolean {
  return (
    /\.(?:create|createMany|update|updateMany|upsert)$/i.test(name) &&
    /(?:prisma|database|\bdb\b|repository|model|supabase|drizzle)/i.test(name)
  );
}

function weakEntropy(node: ts.Node): boolean {
  return /(?:Math\.random\s*\(|Date\.now\s*\(|new\s+Date\s*\(\s*\)\.getTime\s*\()/i.test(
    node.getText(node.getSourceFile()),
  );
}

function caughtErrorExposure(catchClause: ts.CatchClause): ts.CallExpression[] {
  const caught = catchClause.variableDeclaration
    ? bindingNames(catchClause.variableDeclaration.name)
    : ['error', 'err'];
  const exposed: ts.CallExpression[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const name = callName(node);
      if (
        /(?:^|\.)(?:json|send)$/i.test(name) &&
        node.arguments.some((argument) => {
          const text = argument.getText(argument.getSourceFile()).replace(/\s+/g, '');
          return caught.some(
            (identifier) =>
              new RegExp(`\\b${identifier}(?:\\.(?:message|stack|cause))?\\b`).test(text),
          );
        })
      )
        exposed.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(catchClause.block);
  return exposed;
}

function scanFile(parsed: ParsedSource, profile: ProjectProfile): Finding[] {
  const findings: Finding[] = [];
  const tainted = collectTaintedNames(parsed.source);
  const vocabulary = profile.saasSemantics?.vocabulary ?? defaultSaasConfiguration.vocabulary;
  const billingKeys = new Set(vocabulary.billingKeys.map((key) => key.toLowerCase()));
  const assignmentKeys = new Set(
    [...vocabulary.tenantKeys, ...vocabulary.ownerKeys, ...vocabulary.roleKeys].map((key) =>
      key.toLowerCase(),
    ),
  );
  const tokenKeys = new Set(vocabulary.tokenKeys.map((key) => key.toLowerCase()));
  let nodes = 0;

  const add = (candidate: Finding): void => {
    if (findings.length < maximumFindings) findings.push(candidate);
  };
  const visit = (node: ts.Node): void => {
    if (nodes++ > maximumNodesPerFile || findings.length >= maximumFindings) return;
    if (ts.isCallExpression(node)) {
      const name = callName(node);
      if (isBillingSink(name)) {
        for (const property of sensitiveProperties(node, billingKeys, tainted)) {
          if (ts.isPropertyAssignment(property) && isServerOwnedLookup(property.initializer)) continue;
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
      if (isDatabaseMutation(name)) {
        for (const property of sensitiveProperties(node, assignmentKeys, tainted))
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
      }
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

    if (ts.isCatchClause(node))
      for (const call of caughtErrorExposure(node))
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

export function scanSaasSecurity(
  snapshot: Snapshot,
  profile: ProjectProfile,
): SaasSecurityResult {
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
        version: '0.1.0',
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
  const findings = parsed.flatMap((file) => scanFile(file, profile)).slice(0, maximumFindings);
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
        'Four bounded TypeScript/JavaScript rules review client-controlled billing, ownership or privilege assignment, predictable token entropy, and internal error exposure. Findings are source candidates, not runtime proof.',
      version: '0.1.0',
    },
  };
}
