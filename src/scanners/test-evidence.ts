import ts from 'typescript';
import { sensitiveProjectFactKinds } from '../domain/project-graph.ts';
import type {
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
  TestEvidenceAnalysis,
  TestEvidenceReference,
} from '../domain/types.ts';
import { createCapturedImportResolver } from './project-profile.ts';

const sourcePattern = /\.[cm]?[jt]sx?$/i;
const maximumTargets = 500;
const maximumRelatedTests = 20;
const maximumDepth = 5;

function unresolvedSourceSpecifier(specifier: string): boolean {
  if (!(specifier.startsWith('.') || specifier.startsWith('@/') || specifier.startsWith('~/')))
    return false;
  return !/\.[A-Za-z0-9]+$/.test(specifier) || sourcePattern.test(specifier);
}

function scriptKind(file: string): ts.ScriptKind {
  if (/\.[cm]?tsx$/i.test(file)) return ts.ScriptKind.TSX;
  if (/\.jsx$/i.test(file)) return ts.ScriptKind.JSX;
  if (/\.[cm]?js$/i.test(file)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function importedSpecifiers(file: SourceFile): { specifiers: string[]; parseFailed: boolean } {
  const source = ts.createSourceFile(
    file.path,
    file.content,
    ts.ScriptTarget.Latest,
    true,
    scriptKind(file.path),
  );
  const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
    .parseDiagnostics;
  if (diagnostics?.length) return { specifiers: [], parseFailed: true };
  const specifiers = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteralLike(node.moduleSpecifier)
    )
      specifiers.add(node.moduleSpecifier.text);
    if (
      ts.isCallExpression(node) &&
      node.arguments.length === 1 &&
      ts.isStringLiteralLike(node.arguments[0]!) &&
      ((ts.isIdentifier(node.expression) && ['require', 'import'].includes(node.expression.text)) ||
        node.expression.kind === ts.SyntaxKind.ImportKeyword)
    )
      specifiers.add(node.arguments[0]!.text);
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { specifiers: [...specifiers], parseFailed: false };
}

function reachableFrom(
  start: string,
  graph: Map<string, string[]>,
): Map<string, TestEvidenceReference> {
  const reached = new Map<string, TestEvidenceReference>();
  const queue: { file: string; depth: number }[] = [{ file: start, depth: 0 }];
  while (queue.length) {
    const current = queue.shift()!;
    if (current.depth >= maximumDepth) continue;
    for (const target of graph.get(current.file) ?? []) {
      const depth = current.depth + 1;
      const existing = reached.get(target);
      if (existing && existing.depth <= depth) continue;
      reached.set(target, {
        file: start,
        relation: depth === 1 ? 'direct-import' : 'transitive-import',
        depth,
      });
      queue.push({ file: target, depth });
    }
  }
  return reached;
}

export function scanTestEvidence(
  snapshot: Snapshot,
  profile: ProjectProfile,
): { analysis: TestEvidenceAnalysis; run: ScannerRun } {
  const started = performance.now();
  const sourceFiles = snapshot.files.filter((file) => sourcePattern.test(file.path));
  const testFiles = sourceFiles.filter((file) => file.scope === 'test');
  const resolveImport = createCapturedImportResolver(snapshot);
  const graph = new Map<string, string[]>();
  let parseFailures = 0;
  let unresolvedImports = 0;
  for (const file of sourceFiles) {
    const imported = importedSpecifiers(file);
    parseFailures += Number(imported.parseFailed);
    const resolved = new Set<string>();
    for (const specifier of imported.specifiers) {
      const target = resolveImport(file.path, specifier);
      if (target) resolved.add(target);
      else if (unresolvedSourceSpecifier(specifier)) unresolvedImports++;
    }
    graph.set(file.path, [...resolved]);
  }

  const critical = new Map<
    string,
    {
      componentId?: string;
      entrypointIds: string[];
      sensitiveFactIds: string[];
      kinds: Set<ProjectProfile['facts'][number]['kind']>;
    }
  >();
  for (const entrypoint of profile.entrypoints) {
    const target = critical.get(entrypoint.file) ?? {
      ...(entrypoint.componentId ? { componentId: entrypoint.componentId } : {}),
      entrypointIds: [],
      sensitiveFactIds: [],
      kinds: new Set(),
    };
    target.entrypointIds.push(entrypoint.id);
    critical.set(entrypoint.file, target);
  }
  for (const fact of profile.facts.filter((fact) => sensitiveProjectFactKinds.has(fact.kind))) {
    const target = critical.get(fact.file) ?? {
      ...(fact.componentId ? { componentId: fact.componentId } : {}),
      entrypointIds: [],
      sensitiveFactIds: [],
      kinds: new Set(),
    };
    target.sensitiveFactIds.push(fact.id);
    target.kinds.add(fact.kind);
    critical.set(fact.file, target);
  }

  const relatedByTarget = new Map<string, TestEvidenceReference[]>();
  for (const test of testFiles)
    for (const [target, reference] of reachableFrom(test.path, graph))
      if (critical.has(target))
        relatedByTarget.set(target, [...(relatedByTarget.get(target) ?? []), reference]);
  const criticalFiles = [...critical.keys()].sort();
  const targets = criticalFiles.slice(0, maximumTargets).map((file) => {
    const target = critical.get(file)!;
    const related = (relatedByTarget.get(file) ?? []).sort(
      (left, right) => left.depth - right.depth || left.file.localeCompare(right.file),
    );
    return {
      file,
      ...(target.componentId ? { componentId: target.componentId } : {}),
      entrypointIds: target.entrypointIds.slice(0, 100),
      sensitiveFactIds: target.sensitiveFactIds.slice(0, 100),
      sensitiveFactKinds: [...target.kinds].sort(),
      status: related.length ? ('observed' as const) : ('not-observed' as const),
      relatedTests: related.slice(0, maximumRelatedTests),
      truncated:
        target.entrypointIds.length > 100 ||
        target.sensitiveFactIds.length > 100 ||
        related.length > maximumRelatedTests,
    };
  });
  const truncated =
    snapshot.truncated ||
    profile.truncated ||
    criticalFiles.length > maximumTargets ||
    targets.some((target) => target.truncated);
  const status: TestEvidenceAnalysis['status'] =
    profile.status === 'unsupported' || criticalFiles.length === 0
      ? 'unsupported'
      : truncated || parseFailures > 0 || unresolvedImports > 0
        ? 'partial'
        : 'complete';
  const withRelatedTests = targets.filter((target) => target.status === 'observed').length;
  const analysis: TestEvidenceAnalysis = {
    schemaVersion: 1,
    version: '1.0.0',
    status,
    testFiles: testFiles.length,
    criticalFiles: criticalFiles.length,
    withRelatedTests,
    withoutRelatedTests: targets.length - withRelatedTests,
    targets,
    parseFailures,
    unresolvedImports,
    truncated,
    limitations: [
      'A related import is source-reference evidence only; it does not prove that a test asserts the security-relevant behavior.',
      'Tests are not executed, and coverage artifacts are not attributed to individual source files by this analysis.',
      `Import traversal is bounded to ${maximumDepth} resolved captured hops and can miss dynamic loading or unsupported aliases.`,
      'Black-box and end-to-end tests that reach routes only by URL cannot be attributed to source targets mechanically.',
      'Not observed means no related captured test import was found, not that the code is untested.',
    ],
  };
  return {
    analysis,
    run: {
      id: 'test-evidence',
      name: 'Security-critical test evidence',
      status: status === 'unsupported' ? 'skipped' : status === 'partial' ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: 0,
      detail:
        status === 'unsupported'
          ? 'No supported security-critical source target was mapped.'
          : `Mapped ${testFiles.length} captured test file(s) to ${withRelatedTests} of ${criticalFiles.length} security-critical source file(s); ${targets.length - withRelatedTests} have no related captured test import. Tests were not executed.`,
      version: '1.0.0',
    },
  };
}
