import ts from 'typescript';
import type { Finding, ProjectProfile, ScannerRun, Snapshot, SourceFile } from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import { isRuntimeSource } from '../security/paths.ts';

const maximumFindings = 300;
const sourcePattern = /\.[cm]?[jt]sx?$/i;

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function reliabilityFinding(
  file: SourceFile,
  source: ts.SourceFile,
  node: ts.Node,
  ruleId: string,
  title: string,
  description: string,
  remediation: string,
  cwe: string,
  observation: string,
): Finding {
  const evidence = sourceEvidence(file, lineOf(source, node), observation);
  evidence.kind = 'inferred';
  return makeFinding({
    source: 'reliability',
    ruleId,
    title,
    category: 'reliability',
    severity: 'low',
    sourceSeverity: 'review',
    description,
    remediation,
    cwe: [cwe],
    evidence: [evidence],
  });
}

function isFetch(node: ts.CallExpression): boolean {
  const callee = node.expression.getText(node.getSourceFile()).replace(/\s+/g, '');
  return (
    callee === 'fetch' || /^(?:axios|got)\.(?:get|post|put|patch|delete|request)$/.test(callee)
  );
}

function hasTimeout(node: ts.CallExpression): boolean {
  const text = node.getText(node.getSourceFile());
  return /\b(?:signal|timeout)\s*:|AbortSignal\.(?:timeout|any)\s*\(/.test(text);
}

function hasDocumentedRationale(source: ts.SourceFile, node: ts.CatchClause): boolean {
  const blockText = node.block.getText(source).slice(1, -1);
  return /\/\/[^\r\n]*\S|\/\*[\s\S]*?\S[\s\S]*?\*\//.test(blockText);
}

function isExecutableFunction(node: ts.Node): node is
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.ArrowFunction
  | ts.MethodDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

function enclosingFunction(node: ts.Node):
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.ArrowFunction
  | ts.MethodDeclaration
  | undefined {
  let current = node.parent;
  while (current) {
    if (isExecutableFunction(current)) return current;
    current = current.parent;
  }
  return undefined;
}

function hasLaterThrow(node: ts.Node): boolean {
  const scope = enclosingFunction(node);
  if (!scope?.body) return false;
  let found = false;
  const visit = (child: ts.Node): void => {
    if (found || (child !== scope && isExecutableFunction(child))) return;
    if (ts.isThrowStatement(child) && child.getStart() > node.end) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(scope.body);
  return found;
}

function isInsideLoop(node: ts.Node): boolean {
  let current = node.parent;
  while (current) {
    if (
      ts.isForStatement(current) ||
      ts.isForInStatement(current) ||
      ts.isForOfStatement(current) ||
      ts.isWhileStatement(current) ||
      ts.isDoStatement(current)
    )
      return true;
    if (isExecutableFunction(current)) return false;
    current = current.parent;
  }
  return false;
}

function isNestedFailureHandler(node: ts.CatchClause): boolean {
  let current: ts.Node | undefined = node.parent.parent;
  while (current) {
    if (ts.isCatchClause(current)) return true;
    if (ts.isTryStatement(current) && current.finallyBlock) {
      const start = current.finallyBlock.getStart();
      if (node.getStart() >= start && node.end <= current.finallyBlock.end) return true;
    }
    if (isExecutableFunction(current)) return false;
    current = current.parent;
  }
  return false;
}

function isParserProbe(node: ts.CatchClause, source: ts.SourceFile): boolean {
  const tryStatement = node.parent;
  if (!ts.isTryStatement(tryStatement)) return false;
  const attempted = tryStatement.tryBlock.getText(source);
  if (!/\b(?:JSON\.parse|new\s+URL)\s*\(/.test(attempted)) return false;
  return /\breturn\b/.test(attempted) || isInsideLoop(node);
}

function hasExplicitDefaultAssignment(node: ts.CatchClause): boolean {
  const tryStatement = node.parent;
  const block = tryStatement.parent;
  if (!ts.isTryStatement(tryStatement) || !ts.isBlock(block)) return false;
  const assignments = tryStatement.tryBlock.statements.flatMap((statement) => {
    if (!ts.isExpressionStatement(statement)) return [];
    const expression = statement.expression;
    if (
      !ts.isBinaryExpression(expression) ||
      expression.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
      !ts.isIdentifier(expression.left)
    )
      return [];
    return [expression.left.text];
  });
  if (assignments.length !== 1) return false;
  const index = block.statements.indexOf(tryStatement);
  return block.statements.slice(0, index).some((statement) => {
    if (!ts.isVariableStatement(statement)) return false;
    return statement.declarationList.declarations.some(
      (declaration) =>
        ts.isIdentifier(declaration.name) &&
        declaration.name.text === assignments[0] &&
        declaration.initializer !== undefined,
    );
  });
}

function hasExplicitRecovery(node: ts.CatchClause, source: ts.SourceFile): boolean {
  return (
    isNestedFailureHandler(node) ||
    isParserProbe(node, source) ||
    hasExplicitDefaultAssignment(node) ||
    (isInsideLoop(node) && hasLaterThrow(node))
  );
}

function scanFile(
  file: SourceFile,
  requestBoundary: boolean,
): { findings: Finding[]; parseFailed: boolean } {
  const source = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true);
  const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
    .parseDiagnostics;
  if (diagnostics?.length) return { findings: [], parseFailed: true };
  const findings: Finding[] = [];
  const visit = (node: ts.Node): void => {
    if (findings.length >= maximumFindings) return;
    if (requestBoundary && ts.isCallExpression(node) && isFetch(node) && !hasTimeout(node))
      findings.push(
        reliabilityFinding(
          file,
          source,
          node,
          'TW-REL001',
          'Request-bound outbound call has no local timeout evidence',
          'A direct outbound HTTP call in a mapped request boundary has no visible timeout or AbortSignal. Platform or wrapper defaults may still apply.',
          'Apply a bounded timeout or AbortSignal and define how timeout failures are surfaced or retried.',
          'CWE-400',
          'Direct outbound call in a request boundary has no signal or timeout option.',
        ),
      );
    if (
      ts.isCatchClause(node) &&
      node.block.statements.length === 0 &&
      !hasDocumentedRationale(source, node) &&
      !hasExplicitRecovery(node, source)
    )
      findings.push(
        reliabilityFinding(
          file,
          source,
          node,
          'TW-REL002',
          'Caught failure is silently discarded',
          'An undocumented empty catch block discards an exception with no recovery, observability, or explicit rationale.',
          'Handle the expected failure, add bounded observability, rethrow it, or document a narrow intentional ignore next to explicit logic.',
          'CWE-390',
          'Catch block contains no statements or documented rationale.',
        ),
      );
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { findings, parseFailed: false };
}

export function scanReliabilityStatic(
  snapshot: Snapshot,
  profile: ProjectProfile,
): { findings: Finding[]; run: ScannerRun } {
  const started = performance.now();
  const boundaryFiles = new Set(
    profile.entrypoints
      .filter((entrypoint) => entrypoint.kind !== 'middleware')
      .map((entrypoint) => entrypoint.file),
  );
  const files = snapshot.files.filter(
    (file) => isRuntimeSource(file) && sourcePattern.test(file.path),
  );
  const findings: Finding[] = [];
  let parseFailures = 0;
  for (const file of files) {
    const result = scanFile(file, boundaryFiles.has(file.path));
    parseFailures += Number(result.parseFailed);
    findings.push(...result.findings.slice(0, maximumFindings - findings.length));
    if (findings.length >= maximumFindings) break;
  }
  const partial =
    snapshot.truncated ||
    profile.status !== 'complete' ||
    parseFailures > 0 ||
    findings.length >= maximumFindings;
  return {
    findings,
    run: {
      id: 'reliability-static',
      name: 'Static reliability review',
      status: files.length ? (partial ? 'partial' : 'completed') : 'skipped',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: findings.length,
      detail: files.length
        ? `Inspected ${files.length} source file(s) for bounded request-timeout and swallowed-error candidates; ${parseFailures} parse failure(s). Platform timeouts, queues, retries, and runtime recovery remain unverified.`
        : 'No supported runtime source was available for static reliability review.',
      version: '0.3.0',
    },
  };
}
