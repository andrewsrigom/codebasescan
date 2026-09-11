import path from 'node:path';
import ts from 'typescript';
import { digest } from '../domain/findings.ts';
import { buildProjectDataMap } from '../domain/data-map.ts';
import type {
  ProjectCallEdge,
  ProjectComponent,
  ProjectComponentEdge,
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
import {
  declarativeSaasConfiguration,
  declarativeWorkspacePackageEntrypoints,
  typeScriptPathAliases,
  type TrustedSaasConfiguration,
  type TypeScriptPathAlias,
} from './declarative-config.ts';

const sourcePattern = /\.(?:[cm]?[jt]sx?)$/i;
const declarationPattern = /\.d\.[cm]?ts$/i;
const extensions = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];
const maximumFiles = 2000;
const maximumNodesPerFile = 200_000;
const maximumSymbols = 20_000;
const maximumEdges = 50_000;
const maximumCallCandidates = 200_000;
const maximumFacts = 50_000;
const maximumImports = 20_000;
const maximumEntrypoints = 10_000;
const maximumComponents = 200;
const maximumComponentEdges = 1_000;
const maximumImportIdsPerComponentEdge = 20;

interface ParsedFile {
  source: SourceFile;
  ast: ts.SourceFile;
}

interface DependencyDeclaration {
  file: SourceFile;
  requested?: string;
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
    endLine: source.getLineAndCharacterOfPosition(node.end).line + 1,
    name,
    kind,
    exported,
  };
}

function resourceScopeSignal(
  node: ts.CallExpression,
  configuration: TrustedSaasConfiguration,
): string | null {
  const terminal = callName(node.expression).split('.').at(-1) ?? '';
  if (configuration.helpers.resourceScope.some((helper) => helper === terminal)) return terminal;
  const helperScope =
    /(?:for|by)(tenant|owner|user|account|organization|org|workspace|team)(?:id)?$/i.exec(terminal);
  if (helperScope) return helperScope[1]!.toLowerCase();
  const scopeKeys = new Set(
    [...configuration.vocabulary.tenantKeys, ...configuration.vocabulary.ownerKeys].map((key) =>
      key.toLowerCase(),
    ),
  );
  let found: string | null = null;
  let inspected = 0;
  const visit = (child: ts.Node): void => {
    if (found || inspected++ > 2000) return;
    if (ts.isPropertyAssignment(child) || ts.isShorthandPropertyAssignment(child)) {
      const name = propertyName(child.name);
      if (name && scopeKeys.has(name.toLowerCase())) {
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

function factKind(callee: string, configuration: TrustedSaasConfiguration): ProjectFactKind | null {
  const value = callee.toLowerCase();
  const terminal = value.split('.').at(-1) ?? value;
  const configured = Object.entries(configuration.helpers).find(([, helpers]) =>
    helpers.some((helper: string) => helper.toLowerCase() === terminal),
  )?.[0];
  if (configured === 'authentication') return 'authentication';
  if (configured === 'authorization') return 'authorization';
  if (configured === 'validation') return 'validation';
  if (configured === 'rateLimit') return 'rate-limit';
  if (configured === 'idempotency') return 'idempotency';
  if (configured === 'csrf') return 'csrf';
  if (configured === 'auditLog') return 'logging';
  if (
    /(?:^|\.)(?:authorize|requirerole|haspermission|assertaccess|canaccess|checkpermission|throwifnotallowed)$/.test(
      value,
    ) ||
    /^(?:authorize|require|assert|check|can|has|ensure|validate|verify)[a-z0-9]*(?:permission|role|access|owner|admin|policy)[a-z0-9]*$/.test(
      terminal,
    )
  )
    return 'authorization';
  if (
    /(?:^|\.)(?:auth|authenticate|requireuser|requiresession|get(?:server|current)?(?:session|user)(?:withteam)?|currentuser|verifytoken|validatesession|withauth|throwifnoteamaccess)$/.test(
      value,
    ) ||
    /^authenticate[a-z0-9]*$/.test(terminal) ||
    /^require[a-z0-9]*(?:user|session|authentication|auth)[a-z0-9]*$/.test(terminal) ||
    /^get(?:app|auth|server|current)?session(?:withteam)?$/.test(terminal) ||
    /^(?:verify|validate)[a-z0-9]*(?:auth|session|token|credential|apikey|secret|signature)[a-z0-9]*$/.test(
      terminal,
    ) ||
    /^withauth[a-z0-9]*$/.test(terminal)
  )
    return 'authentication';
  if (/^(?:parse|safeparse|validate|validateasync|isvalid|assertvalid)[a-z0-9]*$/.test(terminal))
    return 'validation';
  if (
    /(?:checkout\.sessions|paymentintents|subscriptions|invoiceitems|refunds|transactions)\.(?:create|update|capture|cancel)$/i.test(
      value,
    )
  )
    return 'billing';
  if (/(?:\$queryrawunsafe|\$executerawunsafe|\.raw|\.queryraw)$/.test(value)) return 'raw-sql';
  if (
    /(?:^|\.)(?:findunique|findfirst|findmany|create|update|upsert|delete|executeraw|queryraw|transaction)$/.test(
      value,
    ) &&
    /(?:prisma|database|db|repository|model|client|supabase|drizzle)/.test(value)
  )
    return 'database';
  if (/^(?:fetch|axios|got)(?:\.|$)|\.(?:fetch|request)$/.test(value)) return 'outbound-request';
  if (
    /^(?:exec|execfile|spawn|fork)$/.test(value) ||
    /(?:^|\.)(?:child_process|childprocess)\.(?:exec|execfile|spawn|fork)$/.test(value)
  )
    return 'command-execution';
  if (
    /(?:^|\.)(?:readfile|writefile|appendfile|createwritestream|createreadstream|unlink|rename)$/.test(
      value,
    )
  )
    return 'file-access';
  if (/(?:^|\.)(?:redirect|permanentredirect)$/.test(value)) return 'redirect';
  if (/(?:cookies(?:\(\))?|\.cookies)\.(?:get|set|delete)$|(?:^|\.)cookie$/.test(value))
    return 'cookie';
  if (/(?:^|\.)(?:localstorage|sessionstorage)\.(?:getitem|setitem|removeitem)$/.test(value))
    return 'browser-storage';
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

function packageDependencies(snapshot: Snapshot): Map<string, DependencyDeclaration> {
  const dependencies = new Map<string, DependencyDeclaration>();
  for (const file of snapshot.files.filter(
    (item) => isRuntimeSource(item) && item.path.endsWith('package.json'),
  )) {
    try {
      const parsed = JSON.parse(file.content) as {
        dependencies?: Record<string, unknown>;
        devDependencies?: Record<string, unknown>;
      };
      for (const [name, requested] of Object.entries({
        ...parsed.dependencies,
        ...parsed.devDependencies,
      }))
        if (!dependencies.has(name))
          dependencies.set(name, {
            file,
            ...(typeof requested === 'string' ? { requested: requested.slice(0, 100) } : {}),
          });
    } catch {
      // Inventory reports malformed package manifests separately.
    }
  }
  return dependencies;
}

function componentDeclarations(
  snapshot: Snapshot,
  sourceFiles: SourceFile[],
): { components: ProjectComponent[]; truncated: boolean } {
  const manifests = snapshot.files
    .filter((file) => isRuntimeSource(file) && file.path.endsWith('package.json'))
    .sort((left, right) => {
      const leftRoot = path.posix.dirname(left.path);
      const rightRoot = path.posix.dirname(right.path);
      if (leftRoot === '.') return rightRoot === '.' ? 0 : -1;
      if (rightRoot === '.') return 1;
      return left.path.localeCompare(right.path);
    });
  const declarations = manifests.slice(0, maximumComponents).flatMap((manifest) => {
    try {
      const parsed = JSON.parse(manifest.content) as { name?: unknown; private?: unknown };
      const root = path.posix.dirname(manifest.path);
      const name =
        typeof parsed.name === 'string' && parsed.name.trim()
          ? parsed.name.trim().slice(0, 200)
          : root === '.'
            ? 'root'
            : path.posix.basename(root);
      return [
        {
          id: stableId('component', manifest.path, name),
          name,
          root,
          manifest: manifest.path,
          kind: root === '.' ? ('root' as const) : ('package' as const),
          ...(typeof parsed.private === 'boolean' ? { private: parsed.private } : {}),
        },
      ];
    } catch {
      return [];
    }
  });
  const ordered = [...declarations].sort((left, right) => right.root.length - left.root.length);
  const counts = new Map(declarations.map((component) => [component.id, 0]));
  for (const file of sourceFiles) {
    const owner = ordered.find(
      (component) => component.root === '.' || file.path.startsWith(`${component.root}/`),
    );
    if (owner) counts.set(owner.id, (counts.get(owner.id) ?? 0) + 1);
  }
  return {
    components: declarations.map((component) => ({
      ...component,
      sourceFiles: counts.get(component.id) ?? 0,
    })),
    truncated: manifests.length > maximumComponents,
  };
}

function componentOwner(
  components: ProjectComponent[],
  file: string,
): ProjectComponent | undefined {
  let owner: ProjectComponent | undefined;
  for (const component of components)
    if (
      (component.root === '.' || file.startsWith(`${component.root}/`)) &&
      (!owner || component.root.length > owner.root.length)
    )
      owner = component;
  return owner;
}

function componentImportEdges(
  imports: ProjectImport[],
  components: ProjectComponent[],
): { edges: ProjectComponentEdge[]; truncated: boolean } {
  const grouped = new Map<
    string,
    { fromComponentId: string; toComponentId: string; importIds: string[]; imports: number }
  >();
  for (const item of imports) {
    if (!item.componentId || !item.resolvedFile) continue;
    const target = componentOwner(components, item.resolvedFile);
    if (!target || target.id === item.componentId) continue;
    const key = `${item.componentId}:${target.id}`;
    const group = grouped.get(key) ?? {
      fromComponentId: item.componentId,
      toComponentId: target.id,
      importIds: [],
      imports: 0,
    };
    group.imports++;
    if (group.importIds.length < maximumImportIdsPerComponentEdge) group.importIds.push(item.id);
    grouped.set(key, group);
  }
  const values = [...grouped.values()].sort(
    (left, right) =>
      right.imports - left.imports ||
      `${left.fromComponentId}:${left.toComponentId}`.localeCompare(
        `${right.fromComponentId}:${right.toComponentId}`,
      ),
  );
  return {
    edges: values.slice(0, maximumComponentEdges).map((edge) => ({
      id: stableId('component-edge', edge.fromComponentId, edge.toComponentId),
      ...edge,
      truncated: edge.imports > edge.importIds.length,
    })),
    truncated: values.length > maximumComponentEdges,
  };
}

const supportedFrameworkMajors: Partial<Record<ProjectFramework['id'], readonly number[]>> = {
  'nextjs-app-router': [13, 14, 15, 16],
  'nextjs-pages-router': [12, 13, 14, 15, 16],
  react: [17, 18, 19],
  express: [4, 5],
};

function requestedMajor(requested: string | undefined): number | undefined {
  if (!requested || requested.includes('||')) return undefined;
  const match = /^(?:workspace:)?[~^]?v?(\d+)(?:\.(?:\d+|x|\*)){0,2}(?:-[0-9A-Za-z.-]+)?$/.exec(
    requested.trim(),
  );
  return match?.[1] ? Number.parseInt(match[1], 10) : undefined;
}

function frameworkVersionCoverage(
  id: ProjectFramework['id'],
  declaration?: DependencyDeclaration,
): NonNullable<ProjectFramework['versionCoverage']> {
  const supportedMajors = supportedFrameworkMajors[id];
  const requested = declaration?.requested;
  const detectedMajor = requestedMajor(requested);
  if (!supportedMajors)
    return {
      ...(requested ? { requested } : {}),
      ...(detectedMajor !== undefined ? { detectedMajor } : {}),
      status: 'unverified',
      detail: 'CodebaseScan has no version-specific rule coverage declaration for this framework.',
    };
  if (detectedMajor === undefined)
    return {
      ...(requested ? { requested } : {}),
      status: 'unverified',
      supportedMajors: [...supportedMajors],
      detail: requested
        ? 'The declared range does not identify one framework major, so compatibility remains unverified.'
        : 'No captured package declaration identified a framework major.',
    };
  const supported = supportedMajors.includes(detectedMajor);
  return {
    ...(requested ? { requested } : {}),
    detectedMajor,
    status: supported ? 'supported' : 'partial',
    supportedMajors: [...supportedMajors],
    detail: supported
      ? `Framework major ${detectedMajor} is inside CodebaseScan's declared static-rule support matrix.`
      : `Framework major ${detectedMajor} is outside CodebaseScan's declared static-rule support matrix; generic syntax checks may still apply.`,
  };
}

function frameworkFacts(snapshot: Snapshot, parsed: ParsedFile[]): ProjectFramework[] {
  const frameworks = new Map<ProjectFramework['id'], ProjectFramework>();
  const add = (
    id: ProjectFramework['id'],
    name: string,
    file: string,
    line = 1,
    declaration?: DependencyDeclaration,
  ) => {
    if (!frameworks.has(id))
      frameworks.set(id, {
        id,
        name,
        file,
        line,
        versionCoverage: frameworkVersionCoverage(id, declaration),
      });
  };
  const dependencies = packageDependencies(snapshot);
  const nextManifest = dependencies.get('next');
  const reactManifest = dependencies.get('react');
  const expressManifest = dependencies.get('express');
  const prismaManifest = dependencies.get('@prisma/client') ?? dependencies.get('prisma');
  const drizzleManifest = dependencies.get('drizzle-orm');
  const supabaseManifest = [...dependencies.entries()].find(([name]) =>
    name.startsWith('@supabase/'),
  )?.[1];
  const authManifest = dependencies.get('next-auth') ?? dependencies.get('@auth/core');
  const trpcManifest = dependencies.get('@trpc/server');
  const graphqlManifest =
    dependencies.get('graphql') ??
    dependencies.get('@apollo/server') ??
    dependencies.get('graphql-yoga');
  const zodManifest = dependencies.get('zod');
  const joiManifest = dependencies.get('joi');
  const valibotManifest = dependencies.get('valibot');
  const appRoute = parsed.find((item) =>
    /(?:^|\/)app\/(?:.+\/)?route\.[cm]?[jt]sx?$/.test(item.source.path),
  );
  const pagesRoute = parsed.find((item) =>
    /(?:^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/.test(item.source.path),
  );
  if (appRoute || nextManifest)
    add(
      'nextjs-app-router',
      'Next.js App Router',
      appRoute?.source.path ?? nextManifest!.file.path,
      1,
      nextManifest,
    );
  if (pagesRoute)
    add('nextjs-pages-router', 'Next.js Pages Router', pagesRoute.source.path, 1, nextManifest);
  if (reactManifest) add('react', 'React', reactManifest.file.path, 1, reactManifest);
  if (expressManifest) add('express', 'Express', expressManifest.file.path, 1, expressManifest);
  if (prismaManifest) add('prisma', 'Prisma', prismaManifest.file.path, 1, prismaManifest);
  if (drizzleManifest) add('drizzle', 'Drizzle ORM', drizzleManifest.file.path, 1, drizzleManifest);
  if (supabaseManifest)
    add('supabase', 'Supabase', supabaseManifest.file.path, 1, supabaseManifest);
  if (authManifest) add('authjs', 'Auth.js', authManifest.file.path, 1, authManifest);
  if (trpcManifest) add('trpc', 'tRPC', trpcManifest.file.path, 1, trpcManifest);
  if (graphqlManifest) add('graphql', 'GraphQL', graphqlManifest.file.path, 1, graphqlManifest);
  if (zodManifest) add('zod', 'Zod', zodManifest.file.path, 1, zodManifest);
  if (joiManifest) add('joi', 'Joi', joiManifest.file.path, 1, joiManifest);
  if (valibotManifest) add('valibot', 'Valibot', valibotManifest.file.path, 1, valibotManifest);
  for (const item of parsed) {
    const text = item.source.content;
    if (
      !frameworks.has('express') &&
      /from\s+['"]express['"]|require\(['"]express['"]\)/.test(text)
    )
      add('express', 'Express', item.source.path);
    if (!frameworks.has('react') && /from\s+['"]react(?:\/[^'"]+)?['"]/.test(text))
      add('react', 'React', item.source.path);
    if (!frameworks.has('prisma') && /from\s+['"]@prisma\/client['"]/.test(text))
      add('prisma', 'Prisma', item.source.path);
    if (!frameworks.has('drizzle') && /from\s+['"]drizzle-orm(?:\/[^'"]+)?['"]/.test(text))
      add('drizzle', 'Drizzle ORM', item.source.path);
    if (!frameworks.has('supabase') && /from\s+['"]@supabase\//.test(text))
      add('supabase', 'Supabase', item.source.path);
    if (!frameworks.has('authjs') && /from\s+['"](?:next-auth|@auth\/core)/.test(text))
      add('authjs', 'Auth.js', item.source.path);
    if (!frameworks.has('trpc') && /from\s+['"]@trpc\/server['"]/.test(text))
      add('trpc', 'tRPC', item.source.path);
    if (
      !frameworks.has('graphql') &&
      /from\s+['"](?:graphql|@apollo\/server|graphql-yoga)['"]/.test(text)
    )
      add('graphql', 'GraphQL', item.source.path);
    if (!frameworks.has('zod') && /from\s+['"]zod['"]/.test(text))
      add('zod', 'Zod', item.source.path);
    if (!frameworks.has('joi') && /from\s+['"]joi['"]/.test(text))
      add('joi', 'Joi', item.source.path);
    if (!frameworks.has('valibot') && /from\s+['"]valibot['"]/.test(text))
      add('valibot', 'Valibot', item.source.path);
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

function configuredAliasBases(
  file: string,
  specifier: string,
  aliases: TypeScriptPathAlias[],
): string[] {
  const output: string[] = [];
  const applicable = aliases
    .filter((alias) => {
      const directory = path.posix.dirname(alias.configFile);
      return directory === '.' || file.startsWith(`${directory}/`);
    })
    .sort((left, right) => right.configFile.length - left.configFile.length);
  for (const alias of applicable) {
    const wildcard = alias.pattern.indexOf('*');
    let substitution = '';
    if (wildcard < 0) {
      if (specifier !== alias.pattern) continue;
    } else {
      const prefix = alias.pattern.slice(0, wildcard);
      const suffix = alias.pattern.slice(wildcard + 1);
      if (!specifier.startsWith(prefix) || !specifier.endsWith(suffix)) continue;
      substitution = specifier.slice(prefix.length, specifier.length - suffix.length);
    }
    for (const target of alias.targets)
      output.push(path.posix.normalize(target.replace('*', substitution)));
  }
  return output;
}

function resolveImport(
  file: string,
  specifier: string,
  paths: Set<string>,
  aliases: TypeScriptPathAlias[],
  workspacePackages: Map<string, string>,
): string | undefined {
  const bases = configuredAliasBases(file, specifier, aliases);
  const workspaceTarget = workspacePackages.get(specifier);
  if (workspaceTarget) bases.push(workspaceTarget);
  if (specifier.startsWith('.'))
    bases.push(path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier)));
  else if (specifier.startsWith('@/') || specifier.startsWith('~/')) {
    const root = path.posix.normalize(specifier.slice(2));
    bases.push(root, `src/${root}`);
  } else if (/^[A-Za-z0-9_.-]+\/.+/.test(specifier)) {
    const root = path.posix.normalize(specifier);
    bases.push(root, `src/${root}`);
  } else if (!bases.length) return undefined;

  const candidates = new Set<string>();
  for (const base of bases) {
    candidates.add(base);
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
  }
  return [...candidates].find((candidate) => paths.has(candidate));
}

export function createCapturedImportResolver(
  snapshot: Snapshot,
): (file: string, specifier: string) => string | undefined {
  const paths = new Set(
    snapshot.files.filter((file) => sourcePattern.test(file.path)).map((file) => file.path),
  );
  const aliases = typeScriptPathAliases(snapshot).aliases;
  const workspacePackages = new Map(
    declarativeWorkspacePackageEntrypoints(snapshot).entries.map((entry) => [
      entry.name,
      entry.file,
    ]),
  );
  return (file, specifier) => resolveImport(file, specifier, paths, aliases, workspacePackages);
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
  if (marker === 'pages/api') route = route.replace(/\.[cm]?[jt]sx?$/, '');
  route = route
    .split('/')
    .filter((segment) => segment && !/^\(.+\)$/.test(segment) && !segment.startsWith('@'))
    .join('/');
  return `/${route}`.replace(/\/+/, '/');
}

function dynamicParameters(file: string): string[] {
  return [...file.matchAll(/\[(?:\.\.\.)?([^\]]+)\]/g)].map((match) => match[1]!).slice(0, 20);
}

function httpMethodsInFile(source: ts.SourceFile): string[] {
  const methods = new Set<string>();
  const add = (node: ts.Expression | undefined): void => {
    if (node && ts.isStringLiteralLike(node)) {
      const method = node.text.toUpperCase();
      if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(method)) methods.add(method);
    }
  };
  const visit = (node: ts.Node): void => {
    if (ts.isCaseClause(node)) add(node.expression);
    if (
      ts.isBinaryExpression(node) &&
      [ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.EqualsEqualsEqualsToken].includes(
        node.operatorToken.kind,
      )
    ) {
      if (ts.isPropertyAccessExpression(node.left) && node.left.name.text === 'method')
        add(node.right);
      if (ts.isPropertyAccessExpression(node.right) && node.right.name.text === 'method')
        add(node.left);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return [...methods];
}

function middlewareMatchers(source: ts.SourceFile): string[] {
  const matchers = new Set<string>();
  const collect = (expression: ts.Expression): void => {
    if (ts.isStringLiteralLike(expression)) matchers.add(expression.text.slice(0, 300));
    else if (ts.isArrayLiteralExpression(expression))
      for (const element of expression.elements)
        if (ts.isStringLiteralLike(element)) matchers.add(element.text.slice(0, 300));
  };
  for (const statement of source.statements) {
    if (!ts.isVariableStatement(statement) || !isExported(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (
        !ts.isIdentifier(declaration.name) ||
        !['config', 'proxyConfig'].includes(declaration.name.text) ||
        !declaration.initializer ||
        !ts.isObjectLiteralExpression(declaration.initializer)
      )
        continue;
      for (const property of declaration.initializer.properties)
        if (ts.isPropertyAssignment(property) && propertyName(property.name) === 'matcher')
          collect(property.initializer);
    }
  }
  return [...matchers].slice(0, 20);
}

function addFileEntrypoints(
  item: ParsedFile,
  symbols: ProjectSymbol[],
  entrypoints: ProjectEntrypoint[],
): void {
  const file = item.source.path;
  const allFileSymbols = symbols.filter((symbol) => symbol.file === file);
  const fileSymbols = allFileSymbols.filter((symbol) => symbol.exported);
  const methodPattern = /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/;
  const routeBindings = new Map<string, { line: number; symbolIds: string[] }>();
  for (const symbol of fileSymbols.filter((candidate) => methodPattern.test(candidate.name)))
    routeBindings.set(symbol.name, { line: symbol.line, symbolIds: [symbol.id] });

  for (const statement of item.ast.statements) {
    if (ts.isVariableStatement(statement) && hasModifier(statement, ts.SyntaxKind.ExportKeyword)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name) && methodPattern.test(declaration.name.text)) {
          const callback =
            declaration.initializer && ts.isCallExpression(declaration.initializer)
              ? declaration.initializer.arguments.find(
                  (argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument),
                )
              : undefined;
          const callbackSymbol = callback ? functionSymbol(file, item.ast, callback) : null;
          const callbackIdentifier =
            declaration.initializer && ts.isCallExpression(declaration.initializer)
              ? declaration.initializer.arguments.find(ts.isIdentifier)
              : undefined;
          const callbackIdentifierSymbol = callbackIdentifier
            ? allFileSymbols.find((symbol) => symbol.name === callbackIdentifier.text)
            : undefined;
          const directSymbol = allFileSymbols.find(
            (symbol) => symbol.name === declaration.name.getText(item.ast),
          );
          const aliasedSymbol =
            declaration.initializer && ts.isIdentifier(declaration.initializer)
              ? allFileSymbols.find((symbol) => symbol.name === declaration.initializer!.getText())
              : undefined;
          const target =
            callbackSymbol ?? callbackIdentifierSymbol ?? directSymbol ?? aliasedSymbol;
          routeBindings.set(declaration.name.text, {
            line: lineOf(item.ast, declaration),
            symbolIds: target ? [target.id] : [],
          });
        } else if (ts.isObjectBindingPattern(declaration.name)) {
          for (const element of declaration.name.elements) {
            const method = propertyName(element.name);
            if (method && methodPattern.test(method))
              routeBindings.set(method, { line: lineOf(item.ast, element), symbolIds: [] });
          }
        }
      }
    }
    if (
      ts.isExportDeclaration(statement) &&
      !statement.moduleSpecifier &&
      statement.exportClause &&
      ts.isNamedExports(statement.exportClause)
    )
      for (const element of statement.exportClause.elements) {
        const method = element.name.text;
        if (!methodPattern.test(method)) continue;
        const localName = element.propertyName?.text ?? method;
        const target = allFileSymbols.find((symbol) => symbol.name === localName);
        routeBindings.set(method, {
          line: lineOf(item.ast, element),
          symbolIds: target ? [target.id] : [],
        });
      }
  }
  if (/(?:^|\/)app\/(?:.+\/)?route\.[cm]?[jt]sx?$/.test(file))
    for (const [method, binding] of routeBindings)
      entrypoints.push({
        id: stableId('entrypoint', 'next-route', file, method),
        kind: 'next-route',
        file,
        line: binding.line,
        name: method,
        route: routeFromFile(file, 'app'),
        methods: [method],
        dynamicParameters: dynamicParameters(file),
        symbolIds: [...new Set(binding.symbolIds)],
      });
  if (/(?:^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/.test(file)) {
    entrypoints.push({
      id: stableId('entrypoint', 'next-pages-api', file),
      kind: 'next-pages-api',
      file,
      line: 1,
      name: 'default',
      route: routeFromFile(file, 'pages/api'),
      methods: httpMethodsInFile(item.ast),
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
      matchers: middlewareMatchers(item.ast),
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
  const importedSymbol = (
    file: string,
    name: string,
    depth = 0,
    visited = new Set<string>(),
  ): ProjectSymbol | undefined => {
    if (depth > 5) return undefined;
    const key = `${file}:${name}`;
    if (visited.has(key)) return undefined;
    visited.add(key);
    const local = symbolsByFileAndName.get(key);
    if (local) return local;
    for (const item of importsByFile.get(file) ?? []) {
      if (!item.resolvedFile) continue;
      const binding = item.bindings.find(
        (candidate) => candidate.local === name && candidate.imported !== '*',
      );
      if (!binding) continue;
      const target = importedSymbol(item.resolvedFile, binding.imported, depth + 1, visited);
      if (target) return target;
    }
    return undefined;
  };
  return calls.map((call) => {
    const first = call.callee.split('.')[0] ?? call.callee;
    const last = call.callee.split('.').at(-1) ?? call.callee;
    const local = symbolsByFileAndName.get(`${call.file}:${last}`);
    if (local) return { ...call, targetSymbolId: local.id };
    for (const item of importsByFile.get(call.file) ?? []) {
      if (!item.resolvedFile) continue;
      const binding = item.bindings.find((candidate) => candidate.local === first);
      if (!binding || binding.imported === '*') continue;
      const target = importedSymbol(item.resolvedFile, binding.imported);
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
  const aliasConfiguration = typeScriptPathAliases(snapshot);
  const workspacePackageConfiguration = declarativeWorkspacePackageEntrypoints(snapshot);
  const saasConfiguration = declarativeSaasConfiguration(snapshot);
  const issues: string[] = [
    ...aliasConfiguration.issues,
    ...workspacePackageConfiguration.issues,
    ...saasConfiguration.issues,
  ];
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
  const workspacePackages = new Map(
    workspacePackageConfiguration.entries.map((entry) => [entry.name, entry.file]),
  );
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
          const resolvedFile = resolveImport(
            item.source.path,
            specifier,
            sourcePaths,
            aliasConfiguration.aliases,
            workspacePackages,
          );
          imports.push({
            id: stableId('import', item.source.path, specifier, line),
            file: item.source.path,
            line,
            specifier,
            bindings: importBindings(node).slice(0, 100),
            ...(resolvedFile ? { resolvedFile } : {}),
          });
        }
      }
      if (ts.isCallExpression(node)) {
        const callee = callName(node.expression);
        const line = lineOf(item.ast, node);
        if (!cap(calls.length, maximumCallCandidates, 'Call candidate'))
          calls.push({
            id: stableId('call', item.source.path, line, callee, ownerSymbolId),
            file: item.source.path,
            line,
            callee,
            ...(ownerSymbolId ? { callerSymbolId: ownerSymbolId } : {}),
          });
        const kind = factKind(callee, saasConfiguration.config);
        const callback = node.arguments.find(
          (argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument),
        );
        const callbackSymbol = callback
          ? functionSymbol(item.source.path, item.ast, callback)
          : (node.arguments
              .filter(ts.isIdentifier)
              .map((argument) =>
                symbols.find(
                  (symbol) => symbol.file === item.source.path && symbol.name === argument.text,
                ),
              )
              .find(Boolean) ?? null);
        const factOwnerSymbolId =
          ownerSymbolId ??
          (kind === 'authentication' || kind === 'authorization' ? callbackSymbol?.id : undefined);
        if (kind && !cap(facts.length, maximumFacts, 'Security fact'))
          facts.push({
            id: stableId('fact', kind, item.source.path, line, callee, factOwnerSymbolId),
            kind,
            file: item.source.path,
            line,
            signal: callee,
            ...(factOwnerSymbolId ? { ownerSymbolId: factOwnerSymbolId } : {}),
          });
        const scope =
          kind === 'database' ||
          /(?:^|\.)(?:find|get|create|update|upsert|delete|remove)[A-Za-z0-9_]*$/i.test(callee)
            ? resourceScopeSignal(node, saasConfiguration.config)
            : null;
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
        const trpcProcedure = /(?:^|\.)(query|mutation|subscription)$/i.exec(callee);
        if (
          trpcProcedure &&
          /procedure/i.test(callee) &&
          callbackSymbol &&
          !cap(entrypoints.length, maximumEntrypoints, 'Entrypoint')
        ) {
          const operation = trpcProcedure[1]!.toLowerCase();
          entrypoints.push({
            id: stableId('entrypoint', 'trpc-procedure', item.source.path, line, callee),
            kind: 'trpc-procedure',
            file: item.source.path,
            line,
            name: callee,
            methods: [operation === 'mutation' ? 'POST' : 'GET'],
            dynamicParameters: ['input'],
            symbolIds: [callbackSymbol.id],
          });
          if (
            /(?:protected|authed|authenticated|private|secured)Procedure/i.test(callee) &&
            !cap(facts.length, maximumFacts, 'Security fact')
          )
            facts.push({
              id: stableId('fact', 'authentication', item.source.path, line, callbackSymbol.id),
              kind: 'authentication',
              file: item.source.path,
              line,
              signal: callee.slice(0, 180),
              ownerSymbolId: callbackSymbol.id,
            });
          if (/\.input\s*\(/i.test(callee) && !cap(facts.length, maximumFacts, 'Security fact'))
            facts.push({
              id: stableId('fact', 'validation', item.source.path, line, callbackSymbol.id),
              kind: 'validation',
              file: item.source.path,
              line,
              signal: `${callee.slice(0, 160)} input schema`,
              ownerSymbolId: callbackSymbol.id,
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
      }
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
  const componentResult = componentDeclarations(
    snapshot,
    parsed.map((item) => item.source),
  );
  if (componentResult.truncated) {
    truncated = true;
    issues.push(`Component limit of ${maximumComponents} was reached.`);
  }
  const own = <T extends { file: string }>(items: T[]): T[] =>
    items.map((item) => {
      const component = componentOwner(componentResult.components, item.file);
      return component ? { ...item, componentId: component.id } : item;
    });
  const ownedSymbols = own(symbols);
  const ownedImports = own(imports);
  const resolvedCalls = resolveCallTargets(calls, symbols, imports).filter(
    (call) => call.targetSymbolId,
  );
  if (resolvedCalls.length > maximumEdges) {
    truncated = true;
    issues.push(`Call edge limit of ${maximumEdges} was reached.`);
  }
  const ownedCalls = own(resolvedCalls.slice(0, maximumEdges));
  const ownedFacts = own(facts);
  const ownedEntrypoints = own(entrypoints.slice(0, maximumEntrypoints));
  const frameworks = own(frameworkFacts(snapshot, parsed));
  const componentEdgeResult = componentImportEdges(ownedImports, componentResult.components);
  if (componentEdgeResult.truncated) {
    truncated = true;
    issues.push(`Component import edge limit of ${maximumComponentEdges} was reached.`);
  }
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
    components: componentResult.components,
    componentEdges: componentEdgeResult.edges,
    entrypoints: ownedEntrypoints,
    symbols: ownedSymbols,
    imports: ownedImports,
    calls: ownedCalls,
    facts: ownedFacts,
    saasSemantics: {
      schemaVersion: 1,
      sources: saasConfiguration.sources,
      vocabulary: saasConfiguration.config.vocabulary,
      helpers: saasConfiguration.config.helpers,
      expectedUnauthenticatedRoutes: saasConfiguration.config.expectedUnauthenticatedRoutes,
      ...(saasConfiguration.config.context ? { context: saasConfiguration.config.context } : {}),
      ...(saasConfiguration.config.verification
        ? { verification: saasConfiguration.config.verification }
        : {}),
    },
    dataMap: buildProjectDataMap(ownedFacts, saasConfiguration.config.context),
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
        ? `Parsed ${parsed.length} captured TypeScript/JavaScript file(s) as data; mapped ${entrypoints.length} entry point(s), ${symbols.length} symbol(s), ${ownedCalls.length} resolved call edge(s), ${facts.length} security-relevant fact(s), ${componentResult.components.length} declared component(s), ${componentEdgeResult.edges.length} cross-component import edge(s), ${aliasConfiguration.aliases.length} declarative TypeScript path alias(es), ${workspacePackageConfiguration.entries.length} captured workspace package entry point(s), and ${saasConfiguration.sources.length} declarative SaaS semantics file(s).${issues.length ? ` ${issues.length} profile issue(s) keep coverage partial.` : ''}`
        : 'No supported TypeScript or JavaScript source was available for structural profiling.',
      version: '0.10.1',
    },
  };
}
