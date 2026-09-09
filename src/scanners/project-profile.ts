import path from 'node:path';
import ts from 'typescript';
import { digest } from '../domain/findings.ts';
import type {
  ProjectCallEdge,
  ProjectEntrypoint,
  ProjectFact,
  ProjectFactKind,
  ProjectFramework,
  ProjectImport,
  ProjectImportBinding,
  ProjectProfile,
  ProjectSymbol,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';
import { isRuntimeSource } from '../security/paths.ts';

const sourcePattern = /\.(?:[cm]?[jt]sx?)$/i;
const declarationPattern = /\.d\.[cm]?ts$/i;
const extensions = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];
const maximumFiles = 2000;
const maximumNodesPerFile = 200_000;
const maximumSymbols = 20_000;
const maximumEdges = 50_000;
const maximumFacts = 50_000;
const maximumImports = 20_000;
const maximumEntrypoints = 10_000;

interface ParsedFile {
  source: SourceFile;
  ast: ts.SourceFile;
}

export interface ProjectProfileResult {
  profile: ProjectProfile;
  run: ScannerRun;
}

function stableId(...parts: (string | number | undefined)[]): string {
  return digest(parts.map((part) => String(part ?? '')).join(':')).slice(0, 20);
}

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function scriptKind(file: string): ts.ScriptKind {
  const lower = file.toLowerCase();
  if (lower.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (lower.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (/\.[cm]?js$/.test(lower)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return (
    ts.canHaveModifiers(node) && Boolean(ts.getModifiers(node)?.some((item) => item.kind === kind))
  );
}

function isExported(node: ts.Node): boolean {
  if (hasModifier(node, ts.SyntaxKind.ExportKeyword)) return true;
  if (ts.isVariableDeclaration(node) && ts.isVariableDeclarationList(node.parent)) {
    const statement = node.parent.parent;
    return ts.isVariableStatement(statement) && hasModifier(statement, ts.SyntaxKind.ExportKeyword);
  }
  return false;
}

function propertyName(node: ts.PropertyName | ts.BindingName | undefined): string | null {
  if (!node) return null;
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node))
    return node.text;
  return null;
}

function functionSymbol(file: string, source: ts.SourceFile, node: ts.Node): ProjectSymbol | null {
  let name: string | null = null;
  let kind: ProjectSymbol['kind'] = 'function';
  let exported = isExported(node);
  if (ts.isFunctionDeclaration(node)) name = node.name?.text ?? null;
  else if (ts.isMethodDeclaration(node)) {
    name = propertyName(node.name);
    kind = 'method';
  } else if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    ts.isVariableDeclaration(node.parent)
  ) {
    name = propertyName(node.parent.name);
    kind = ts.isArrowFunction(node) ? 'arrow-function' : 'function';
    exported = isExported(node.parent);
  } else if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    ts.isCallExpression(node.parent)
  ) {
    name = `callback@${lineOf(source, node)}`;
    kind = ts.isArrowFunction(node) ? 'arrow-function' : 'function';
  }
  if (!name) return null;
  const line = lineOf(source, node);
  return {
    id: stableId('symbol', file, name, line),
    file,
    line,
    name,
    kind,
    exported,
  };
}

function resourceScopeSignal(node: ts.CallExpression): string | null {
  let found: string | null = null;
  let inspected = 0;
  const visit = (child: ts.Node): void => {
    if (found || inspected++ > 2000) return;
    if (ts.isPropertyAssignment(child) || ts.isShorthandPropertyAssignment(child)) {
      const name = propertyName(child.name);
      if (
        name &&
        /^(?:tenant|tenantId|owner|ownerId|userId|accountId|organizationId|orgId)$/i.test(name)
      ) {
        found = name;
        return;
      }
    }
    ts.forEachChild(child, visit);
  };
  for (const argument of node.arguments) visit(argument);
  return found;
}

function callName(expression: ts.Expression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) {
    const left = callName(expression.expression);
    return `${left ? `${left}.` : ''}${expression.name.text}`.slice(-180);
  }
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression) {
    const left = callName(expression.expression);
    const argument = expression.argumentExpression;
    if (ts.isStringLiteralLike(argument)) return `${left}.${argument.text}`.slice(-180);
  }
  return expression.getText().replace(/\s+/g, ' ').slice(0, 180);
}

function factKind(callee: string): ProjectFactKind | null {
  const value = callee.toLowerCase();
  if (
    /(?:^|\.)(?:auth|authenticate|requireuser|requiresession|getserver(?:session|user)|currentuser|verifytoken|validatesession|withauth)$/.test(
      value,
    )
  )
    return 'authentication';
  if (
    /(?:^|\.)(?:authorize|requirerole|haspermission|assertaccess|canaccess|checkpermission)$/.test(
      value,
    )
  )
    return 'authorization';
  if (/(?:^|\.)(?:parse|safeparse|validate|validateasync|isvalid)$/.test(value))
    return 'validation';
  if (/(?:\$queryrawunsafe|\$executerawunsafe|\.raw|\.queryraw)$/.test(value)) return 'raw-sql';
  if (
    /(?:^|\.)(?:findunique|findfirst|findmany|create|update|upsert|delete|executeraw|queryraw|transaction)$/.test(
      value,
    ) &&
    /(?:prisma|database|db|repository|model|client)/.test(value)
  )
    return 'database';
  if (/^(?:fetch|axios|got)(?:\.|$)|\.(?:fetch|request)$/.test(value)) return 'outbound-request';
  if (/(?:^|\.)(?:exec|execfile|spawn|fork)$/.test(value)) return 'command-execution';
  if (
    /(?:^|\.)(?:readfile|writefile|appendfile|createwritestream|createreadstream|unlink|rename)$/.test(
      value,
    )
  )
    return 'file-access';
  if (/(?:^|\.)(?:redirect|permanentredirect)$/.test(value)) return 'redirect';
  if (/(?:cookies(?:\(\))?|\.cookies)\.(?:get|set|delete)$|(?:^|\.)cookie$/.test(value))
    return 'cookie';
  if (/(?:^|\.)(?:json|send|nextresponse\.json|response\.json)$/.test(value)) return 'response';
  if (
    /(?:^|\.)(?:verifywebhook|verifysignature|constructevent|verifyhmac|checksignature)$/.test(
      value,
    )
  )
    return 'webhook-verification';
  if (
    /(?:^|\.)(?:auditlog|recordaudit|logsecurityevent)$|(?:audit|securitylogger)\.(?:log|record|write)$/.test(
      value,
    )
  )
    return 'logging';
  return null;
}

function packageDependencies(snapshot: Snapshot): Map<string, SourceFile> {
  const dependencies = new Map<string, SourceFile>();
  for (const file of snapshot.files.filter(
    (item) => isRuntimeSource(item) && item.path.endsWith('package.json'),
  )) {
    try {
      const parsed = JSON.parse(file.content) as {
        dependencies?: Record<string, unknown>;
        devDependencies?: Record<string, unknown>;
      };
      for (const name of Object.keys({ ...parsed.dependencies, ...parsed.devDependencies }))
        if (!dependencies.has(name)) dependencies.set(name, file);
    } catch {
      // Inventory reports malformed package manifests separately.
    }
  }
  return dependencies;
}

function frameworkFacts(snapshot: Snapshot, parsed: ParsedFile[]): ProjectFramework[] {
  const frameworks = new Map<ProjectFramework['id'], ProjectFramework>();
  const add = (id: ProjectFramework['id'], name: string, file: string, line = 1) => {
    if (!frameworks.has(id)) frameworks.set(id, { id, name, file, line });
  };
  const dependencies = packageDependencies(snapshot);
  const nextManifest = dependencies.get('next');
  const expressManifest = dependencies.get('express');
  const prismaManifest = dependencies.get('@prisma/client') ?? dependencies.get('prisma');
  const supabaseManifest = [...dependencies.entries()].find(([name]) =>
    name.startsWith('@supabase/'),
  )?.[1];
  const appRoute = parsed.find((item) =>
    /(?:^|\/)app\/.+\/route\.[cm]?[jt]sx?$/.test(item.source.path),
  );
  const pagesRoute = parsed.find((item) =>
    /(?:^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/.test(item.source.path),
  );
  if (appRoute || nextManifest)
    add('nextjs-app-router', 'Next.js App Router', appRoute?.source.path ?? nextManifest!.path);
  if (pagesRoute) add('nextjs-pages-router', 'Next.js Pages Router', pagesRoute.source.path);
  if (expressManifest) add('express', 'Express', expressManifest.path);
  if (prismaManifest) add('prisma', 'Prisma', prismaManifest.path);
  if (supabaseManifest) add('supabase', 'Supabase', supabaseManifest.path);
  for (const item of parsed) {
    const text = item.source.content;
    if (
      !frameworks.has('express') &&
      /from\s+['"]express['"]|require\(['"]express['"]\)/.test(text)
    )
      add('express', 'Express', item.source.path);
    if (!frameworks.has('prisma') && /from\s+['"]@prisma\/client['"]/.test(text))
      add('prisma', 'Prisma', item.source.path);
    if (!frameworks.has('supabase') && /from\s+['"]@supabase\//.test(text))
      add('supabase', 'Supabase', item.source.path);
  }
  return [...frameworks.values()];
}

function importBindings(node: ts.ImportDeclaration): ProjectImportBinding[] {
  const clause = node.importClause;
  if (!clause) return [];
  const bindings: ProjectImportBinding[] = [];
  if (clause.name) bindings.push({ imported: 'default', local: clause.name.text });
  if (clause.namedBindings) {
    if (ts.isNamespaceImport(clause.namedBindings))
      bindings.push({ imported: '*', local: clause.namedBindings.name.text });
    else
      for (const element of clause.namedBindings.elements)
        bindings.push({
          imported: element.propertyName?.text ?? element.name.text,
          local: element.name.text,
        });
  }
  return bindings;
}

function resolveImport(file: string, specifier: string, paths: Set<string>): string | undefined {
  if (!specifier.startsWith('.')) return undefined;
  const directory = path.posix.dirname(file);
  const base = path.posix.normalize(path.posix.join(directory, specifier));
  const candidates = new Set<string>([base]);
  const extension = path.posix.extname(base);
  if (extension) {
    const stem = base.slice(0, -extension.length);
    if (['.js', '.jsx', '.mjs', '.cjs'].includes(extension))
      for (const candidate of extensions) candidates.add(`${stem}${candidate}`);
  } else {
    for (const candidate of extensions) {
      candidates.add(`${base}${candidate}`);
      candidates.add(`${base}/index${candidate}`);
    }
  }
  return [...candidates].find((candidate) => paths.has(candidate));
}

function hasUseServerDirective(statements: ts.NodeArray<ts.Statement>): boolean {
  for (const statement of statements) {
    if (!ts.isExpressionStatement(statement) || !ts.isStringLiteral(statement.expression))
      return false;
    if (statement.expression.text === 'use server') return true;
  }
  return false;
}

function isServerActionFile(source: ts.SourceFile): boolean {
  return hasUseServerDirective(source.statements);
}

function isInlineServerAction(node: ts.Node): boolean {
  return (
    (ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)) &&
    Boolean(node.body && ts.isBlock(node.body) && hasUseServerDirective(node.body.statements))
  );
}

function routeFromFile(file: string, marker: 'app' | 'pages/api'): string {
  const normalized = file.replace(/^src\//, '');
  const start = normalized.indexOf(`${marker}/`);
  if (start < 0) return '/';
  let route = normalized
    .slice(start + marker.length)
    .replace(/\/(?:route|index)\.[cm]?[jt]sx?$/, '');
  route = route
    .split('/')
    .filter((segment) => segment && !/^\(.+\)$/.test(segment) && !segment.startsWith('@'))
    .join('/');
  return `/${route}`.replace(/\/+/, '/');
}

function dynamicParameters(file: string): string[] {
  return [...file.matchAll(/\[(?:\.\.\.)?([^\]]+)\]/g)].map((match) => match[1]!).slice(0, 20);
}

function addFileEntrypoints(
  item: ParsedFile,
  symbols: ProjectSymbol[],
  entrypoints: ProjectEntrypoint[],
): void {
  const file = item.source.path;
  const allFileSymbols = symbols.filter((symbol) => symbol.file === file);
  const fileSymbols = allFileSymbols.filter((symbol) => symbol.exported);
  const routeMethods = fileSymbols.filter((symbol) =>
    /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(symbol.name),
  );
  if (/(?:^|\/)app\/.+\/route\.[cm]?[jt]sx?$/.test(file) && routeMethods.length) {
    entrypoints.push({
      id: stableId('entrypoint', 'next-route', file),
      kind: 'next-route',
      file,
      line: Math.min(...routeMethods.map((symbol) => symbol.line)),
      name: routeMethods.map((symbol) => symbol.name).join(', '),
      route: routeFromFile(file, 'app'),
      methods: routeMethods.map((symbol) => symbol.name),
      dynamicParameters: dynamicParameters(file),
      symbolIds: routeMethods.map((symbol) => symbol.id),
    });
  }
  if (/(?:^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/.test(file)) {
    entrypoints.push({
      id: stableId('entrypoint', 'next-pages-api', file),
      kind: 'next-pages-api',
      file,
      line: 1,
      name: 'default',
      route: routeFromFile(file, 'pages/api'),
      methods: [],
      dynamicParameters: dynamicParameters(file),
      symbolIds: fileSymbols.map((symbol) => symbol.id).slice(0, 20),
    });
  }
  if (isServerActionFile(item.ast))
    for (const symbol of fileSymbols)
      entrypoints.push({
        id: stableId('entrypoint', 'server-action', file, symbol.name, symbol.line),
        kind: 'server-action',
        file,
        line: symbol.line,
        name: symbol.name,
        methods: [],
        dynamicParameters: [],
        symbolIds: [symbol.id],
      });
  const inlineActionIds = new Set<string>();
  const visitInlineActions = (node: ts.Node): void => {
    if (isInlineServerAction(node)) {
      const candidate = functionSymbol(file, item.ast, node);
      const symbol = candidate
        ? allFileSymbols.find((itemSymbol) => itemSymbol.id === candidate.id)
        : undefined;
      if (symbol && !inlineActionIds.has(symbol.id)) {
        inlineActionIds.add(symbol.id);
        entrypoints.push({
          id: stableId('entrypoint', 'server-action', file, symbol.name, symbol.line),
          kind: 'server-action',
          file,
          line: symbol.line,
          name: symbol.name,
          methods: [],
          dynamicParameters: [],
          symbolIds: [symbol.id],
        });
      }
    }
    ts.forEachChild(node, visitInlineActions);
  };
  visitInlineActions(item.ast);
  const base = path.posix.basename(file);
  if (/^(?:middleware|proxy)\.[cm]?[jt]sx?$/.test(base))
    entrypoints.push({
      id: stableId('entrypoint', 'middleware', file),
      kind: 'middleware',
      file,
      line: 1,
      name: base.startsWith('proxy.') ? 'proxy' : 'middleware',
      methods: [],
      dynamicParameters: [],
      symbolIds: fileSymbols.map((symbol) => symbol.id).slice(0, 20),
    });
}

function resolveCallTargets(
  calls: ProjectCallEdge[],
  symbols: ProjectSymbol[],
  imports: ProjectImport[],
): ProjectCallEdge[] {
  const symbolsByFileAndName = new Map(
    symbols.map((symbol) => [`${symbol.file}:${symbol.name}`, symbol]),
  );
  const importsByFile = new Map<string, ProjectImport[]>();
  for (const item of imports)
    importsByFile.set(item.file, [...(importsByFile.get(item.file) ?? []), item]);
  return calls.map((call) => {
    const first = call.callee.split('.')[0] ?? call.callee;
    const last = call.callee.split('.').at(-1) ?? call.callee;
    const local = symbolsByFileAndName.get(`${call.file}:${last}`);
    if (local) return { ...call, targetSymbolId: local.id };
    for (const item of importsByFile.get(call.file) ?? []) {
      if (!item.resolvedFile) continue;
      const binding = item.bindings.find((candidate) => candidate.local === first);
      if (!binding || binding.imported === '*') continue;
      const target = symbolsByFileAndName.get(`${item.resolvedFile}:${binding.imported}`);
      if (target) return { ...call, targetSymbolId: target.id };
    }
    return call;
  });
}

export function profileProject(snapshot: Snapshot): ProjectProfileResult {
  const started = performance.now();
  const candidates = snapshot.files.filter(
    (file) =>
      isRuntimeSource(file) && sourcePattern.test(file.path) && !declarationPattern.test(file.path),
  );
  const issues: string[] = [];
  let truncated = snapshot.truncated || candidates.length > maximumFiles;
  if (candidates.length > maximumFiles)
    issues.push(`Source profiling was limited to ${maximumFiles} files.`);
  const parsed: ParsedFile[] = [];
  let nodesAnalyzed = 0;
  for (const file of candidates.slice(0, maximumFiles)) {
    const ast = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    const diagnostics = (ast as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
      .parseDiagnostics;
    if (diagnostics?.length)
      issues.push(`${file.path}: ${diagnostics.length} syntax diagnostic(s).`);
    parsed.push({ source: file, ast });
  }

  const symbols: ProjectSymbol[] = [];
  const imports: ProjectImport[] = [];
  const calls: ProjectCallEdge[] = [];
  const facts: ProjectFact[] = [];
  const entrypoints: ProjectEntrypoint[] = [];
  const sourcePaths = new Set(parsed.map((item) => item.source.path));
  const cap = (current: number, maximum: number, label: string): boolean => {
    if (current < maximum) return false;
    truncated = true;
    if (!issues.some((issue) => issue.includes(`${label} limit`)))
      issues.push(`${label} limit of ${maximum} was reached.`);
    return true;
  };

  for (const item of parsed) {
    let fileNodes = 0;
    const visit = (node: ts.Node, ownerSymbolId?: string): void => {
      fileNodes++;
      nodesAnalyzed++;
      if (fileNodes > maximumNodesPerFile) {
        truncated = true;
        if (!issues.some((issue) => issue.startsWith(`${item.source.path}: AST`)))
          issues.push(`${item.source.path}: AST node limit of ${maximumNodesPerFile} was reached.`);
        return;
      }
      let nextOwner = ownerSymbolId;
      const symbol = functionSymbol(item.source.path, item.ast, node);
      if (symbol) {
        if (!cap(symbols.length, maximumSymbols, 'Symbol')) symbols.push(symbol);
        nextOwner = symbol.id;
      }
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        if (!cap(imports.length, maximumImports, 'Import')) {
          const specifier = node.moduleSpecifier.text.slice(0, 300);
          const line = lineOf(item.ast, node);
          imports.push({
            id: stableId('import', item.source.path, specifier, line),
            file: item.source.path,
            line,
            specifier,
            bindings: importBindings(node).slice(0, 100),
            ...(resolveImport(item.source.path, specifier, sourcePaths)
              ? { resolvedFile: resolveImport(item.source.path, specifier, sourcePaths) }
              : {}),
          });
        }
      }
      if (ts.isCallExpression(node)) {
        const callee = callName(node.expression);
        const line = lineOf(item.ast, node);
        if (!cap(calls.length, maximumEdges, 'Call edge'))
          calls.push({
            id: stableId('call', item.source.path, line, callee, ownerSymbolId),
            file: item.source.path,
            line,
            callee,
            ...(ownerSymbolId ? { callerSymbolId: ownerSymbolId } : {}),
          });
        const kind = factKind(callee);
        if (kind && !cap(facts.length, maximumFacts, 'Security fact'))
          facts.push({
            id: stableId('fact', kind, item.source.path, line, callee, ownerSymbolId),
            kind,
            file: item.source.path,
            line,
            signal: callee,
            ...(ownerSymbolId ? { ownerSymbolId } : {}),
          });
        const scope = kind === 'database' ? resourceScopeSignal(node) : null;
        if (scope && !cap(facts.length, maximumFacts, 'Security fact'))
          facts.push({
            id: stableId('fact', 'resource-scope', item.source.path, line, scope, ownerSymbolId),
            kind: 'resource-scope',
            file: item.source.path,
            line,
            signal: scope,
            ...(ownerSymbolId ? { ownerSymbolId } : {}),
          });
        const route = /^(?:app|router)\.(get|post|put|patch|delete|head|options|use)$/i.exec(
          callee,
        );
        const routeArgument = node.arguments[0];
        if (
          route &&
          routeArgument &&
          ts.isStringLiteralLike(routeArgument) &&
          !cap(entrypoints.length, maximumEntrypoints, 'Entrypoint')
        ) {
          const handler = node.arguments.at(-1);
          const handlerSymbol = handler
            ? functionSymbol(item.source.path, item.ast, handler)
            : null;
          entrypoints.push({
            id: stableId('entrypoint', 'express-route', item.source.path, line, callee),
            kind: 'express-route',
            file: item.source.path,
            line,
            name: callee,
            route: routeArgument.text.slice(0, 300),
            methods: [route[1]!.toUpperCase()],
            dynamicParameters: [...routeArgument.text.matchAll(/:([A-Za-z0-9_]+)/g)].map(
              (match) => match[1]!,
            ),
            symbolIds: handlerSymbol ? [handlerSymbol.id] : ownerSymbolId ? [ownerSymbolId] : [],
          });
        }
      }
      if (
        ts.isPropertyAccessExpression(node) &&
        node.expression.getText(item.ast) === 'process.env' &&
        !cap(facts.length, maximumFacts, 'Security fact')
      ) {
        const line = lineOf(item.ast, node);
        facts.push({
          id: stableId('fact', 'secret-access', item.source.path, line, node.name.text),
          kind: 'secret-access',
          file: item.source.path,
          line,
          signal: `process.env.${node.name.text}`.slice(0, 180),
          ...(ownerSymbolId ? { ownerSymbolId } : {}),
        });
        if (
          ts.isCatchClause(node) &&
          ownerSymbolId &&
          !cap(facts.length, maximumFacts, 'Security fact')
        ) {
          const line = lineOf(item.ast, node);
          facts.push({
            id: stableId('fact', 'error-handling', item.source.path, line, ownerSymbolId),
            kind: 'error-handling',
            file: item.source.path,
            line,
            signal: 'catch clause',
            ownerSymbolId,
          });
        }
      }
      ts.forEachChild(node, (child) => visit(child, nextOwner));
    };
    visit(item.ast);
    if (!cap(entrypoints.length, maximumEntrypoints, 'Entrypoint'))
      addFileEntrypoints(item, symbols, entrypoints);
  }

  const languages = [
    ...(parsed.some((item) => /\.[cm]?tsx?$/.test(item.source.path))
      ? (['typescript'] as const)
      : []),
    ...(parsed.some((item) => /\.[cm]?jsx?$/.test(item.source.path))
      ? (['javascript'] as const)
      : []),
  ];
  const frameworks = frameworkFacts(snapshot, parsed);
  const status: ProjectProfile['status'] = !parsed.length
    ? 'unsupported'
    : truncated || issues.length
      ? 'partial'
      : 'complete';
  const profile: ProjectProfile = {
    schemaVersion: 1,
    status,
    languages,
    frameworks,
    entrypoints: entrypoints.slice(0, maximumEntrypoints),
    symbols,
    imports,
    calls: resolveCallTargets(calls, symbols, imports),
    facts,
    filesAnalyzed: parsed.length,
    nodesAnalyzed,
    issues: issues.slice(0, 200),
    truncated,
  };
  return {
    profile,
    run: {
      id: 'project-profile',
      name: 'Project structure profile',
      status: status === 'complete' ? 'completed' : status === 'partial' ? 'partial' : 'skipped',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: 0,
      detail: parsed.length
        ? `Parsed ${parsed.length} captured TypeScript/JavaScript file(s) as data; mapped ${entrypoints.length} entry point(s), ${symbols.length} symbol(s), ${calls.length} call edge(s), and ${facts.length} security-relevant fact(s).${issues.length ? ` ${issues.length} profile issue(s) keep coverage partial.` : ''}`
        : 'No supported TypeScript or JavaScript source was available for structural profiling.',
      version: '0.1.0',
    },
  };
}
