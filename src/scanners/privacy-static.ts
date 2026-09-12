import ts from 'typescript';
import type { Finding, ScannerRun, Snapshot, SourceFile } from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import { isRuntimeSource } from '../security/paths.ts';

const maximumFindings = 300;
const sourcePattern = /\.[cm]?[jt]sx?$/i;
const sensitive =
  /(?:access[_-]?token|address|authorization|card|cookie|credential|date[_-]?of[_-]?birth|dob|email|jwt|password|phone|refresh[_-]?token|secret|session|ssn|tax[_-]?id)/i;
const protectedValue = /(?:hash|mask|redact|sanitize|tokenize)\w*\s*\(/i;
const protectedIdentifier = /(?:hashed|masked|redacted|sanitized|tokenized)/i;
const safeAggregateProperty = /^(?:length|size)$/i;

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function callName(expression: ts.Expression): string {
  return expression.getText(expression.getSourceFile()).replace(/\s+/g, '').slice(-160);
}

function stringValue(expression: ts.Expression | undefined): string | undefined {
  return expression && ts.isStringLiteralLike(expression) ? expression.text : undefined;
}

function containsSensitiveUnprotectedValue(expression: ts.Expression): boolean {
  const source = expression.getSourceFile();
  if (ts.isStringLiteralLike(expression) || ts.isNoSubstitutionTemplateLiteral(expression))
    return false;
  if (ts.isIdentifier(expression))
    return sensitive.test(expression.text) && !protectedIdentifier.test(expression.text);
  if (ts.isTemplateExpression(expression))
    return expression.templateSpans.some((span) =>
      containsSensitiveUnprotectedValue(span.expression),
    );
  if (ts.isCallExpression(expression)) {
    if (protectedValue.test(expression.getText(source))) return false;
    const name = callName(expression.expression);
    if (/errorCode$/i.test(name))
      return expression.arguments.some(containsSensitiveUnprotectedValue);
    return sensitive.test(name) || expression.arguments.some(containsSensitiveUnprotectedValue);
  }
  if (ts.isPropertyAccessExpression(expression)) {
    if (safeAggregateProperty.test(expression.name.text)) return false;
    return (
      sensitive.test(expression.name.text) ||
      containsSensitiveUnprotectedValue(expression.expression)
    );
  }
  if (ts.isElementAccessExpression(expression))
    return (
      containsSensitiveUnprotectedValue(expression.expression) ||
      (expression.argumentExpression
        ? containsSensitiveUnprotectedValue(expression.argumentExpression)
        : false)
    );
  if (ts.isObjectLiteralExpression(expression))
    return expression.properties.some((property) => {
      if (ts.isPropertyAssignment(property))
        return containsSensitiveUnprotectedValue(property.initializer);
      if (ts.isShorthandPropertyAssignment(property))
        return containsSensitiveUnprotectedValue(property.name);
      if (ts.isSpreadAssignment(property))
        return containsSensitiveUnprotectedValue(property.expression);
      return false;
    });
  let found = false;
  ts.forEachChild(expression, (child) => {
    if (found || !ts.isExpression(child)) return;
    found = containsSensitiveUnprotectedValue(child);
  });
  return found;
}

function privacyFinding(
  file: SourceFile,
  source: ts.SourceFile,
  node: ts.Node,
  ruleId: string,
  title: string,
  severity: 'medium' | 'low',
  description: string,
  remediation: string,
  cwe: string,
  observation: string,
): Finding {
  const evidence = sourceEvidence(file, lineOf(source, node), observation);
  evidence.kind = 'inferred';
  return makeFinding({
    source: 'privacy',
    ruleId,
    title,
    category: 'privacy',
    severity,
    sourceSeverity: 'review',
    description,
    remediation,
    cwe: [cwe],
    evidence: [evidence],
  });
}

function scanFile(file: SourceFile): { findings: Finding[]; parseFailed: boolean } {
  const source = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true);
  const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
    .parseDiagnostics;
  if (diagnostics?.length) return { findings: [], parseFailed: true };
  const findings: Finding[] = [];
  const visit = (node: ts.Node): void => {
    if (findings.length >= maximumFindings) return;
    if (ts.isCallExpression(node)) {
      const callee = callName(node.expression);
      const key = stringValue(node.arguments[0]);
      if (
        key &&
        sensitive.test(key) &&
        /(?:urlsearchparams|searchparams|query|params)\.(?:set|append)$/i.test(callee)
      )
        findings.push(
          privacyFinding(
            file,
            source,
            node,
            'TW-PRIV001',
            'Sensitive-shaped value is placed in a URL parameter',
            'medium',
            'A URL or search-parameter key names credential or personal data. URLs can reach histories, logs, referrers, and monitoring systems.',
            'Keep sensitive values out of URLs. Use a protected request body or an opaque, short-lived reference where appropriate.',
            'CWE-598',
            `Sensitive-shaped URL parameter key: ${key}.`,
          ),
        );
      if (
        /(?:^|\.)(?:console|logger|log)\.(?:debug|info|log|warn|error)$/i.test(callee) &&
        node.arguments.some(containsSensitiveUnprotectedValue)
      )
        findings.push(
          privacyFinding(
            file,
            source,
            node,
            'TW-PRIV002',
            'Sensitive-shaped data may enter application logs',
            'medium',
            'A logging call directly references a credential- or personal-data-shaped value without visible redaction.',
            'Log stable event metadata and identifiers. Redact, mask, hash, or omit sensitive values before serialization.',
            'CWE-532',
            'Logging arguments include a sensitive-shaped identifier without a visible protection call.',
          ),
        );
      if (key && sensitive.test(key) && /(?:localstorage|sessionstorage)\.setitem$/i.test(callee))
        findings.push(
          privacyFinding(
            file,
            source,
            node,
            'TW-PRIV003',
            'Sensitive-shaped data is written to browser storage',
            'medium',
            'Browser storage is script-readable and persistent beyond the immediate request or component lifecycle.',
            'Avoid browser persistence for credentials and sensitive personal data. Prefer server-managed sessions or the minimum short-lived non-sensitive state.',
            'CWE-922',
            `Sensitive-shaped browser-storage key: ${key}.`,
          ),
        );
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { findings, parseFailed: false };
}

export function scanPrivacyStatic(snapshot: Snapshot): { findings: Finding[]; run: ScannerRun } {
  const started = performance.now();
  const files = snapshot.files.filter(
    (file) => isRuntimeSource(file) && sourcePattern.test(file.path),
  );
  const findings: Finding[] = [];
  let parseFailures = 0;
  for (const file of files) {
    const result = scanFile(file);
    parseFailures += Number(result.parseFailed);
    findings.push(...result.findings.slice(0, maximumFindings - findings.length));
    if (findings.length >= maximumFindings) break;
  }
  const partial = snapshot.truncated || parseFailures > 0 || findings.length >= maximumFindings;
  return {
    findings,
    run: {
      id: 'privacy-static',
      name: 'Static privacy review',
      status: files.length ? (partial ? 'partial' : 'completed') : 'skipped',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: findings.length,
      detail: files.length
        ? `Inspected ${files.length} source file(s) for bounded URL, logging, and browser-storage privacy candidates; ${parseFailures} parse failure(s). Data purpose, retention, consent, and runtime transfers remain unverified.`
        : 'No supported runtime source was available for static privacy review.',
      version: '0.4.1',
    },
  };
}
