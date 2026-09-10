import { parseDocument } from 'yaml';
import { digest } from '../domain/findings.ts';
import type {
  ApiContractAnalysis,
  ApiContractOperation,
  ApiSourceOperation,
  ProjectEntrypoint,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';

const specificationPattern = /(?:^|\/)(?:openapi|swagger)(?:\.[^.\/]+)?\.(?:json|ya?ml)$/i;
const structuredPattern = /\.(?:json|ya?ml)$/i;
const supportedMethods = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
  'TRACE',
]);
const routeEntrypointKinds = new Set<ProjectEntrypoint['kind']>([
  'next-route',
  'next-pages-api',
  'express-route',
]);
const maximumSpecifications = 20;
const maximumOperations = 1_000;
const maximumSourceOperations = 2_000;

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseStructured(file: SourceFile): Record<string, unknown> | null {
  try {
    if (file.path.endsWith('.json')) return object(JSON.parse(file.content));
    const document = parseDocument(file.content, { schema: 'core' });
    if (document.errors.length) return null;
    return object(document.toJS({ maxAliasCount: 100 }));
  } catch {
    return null;
  }
}

function looksLikeSpecification(file: SourceFile): boolean {
  if (!structuredPattern.test(file.path) || file.scope !== 'runtime') return false;
  if (specificationPattern.test(file.path)) return true;
  return /(?:^|\n)\s*(?:["']?openapi["']?|["']?swagger["']?)\s*:/m.test(file.content);
}

function normalizeRoute(route: string): string {
  const withoutQuery = route.trim().split(/[?#]/, 1)[0] || '/';
  const segments = withoutQuery
    .replace(/\\/g, '/')
    .split('/')
    .filter(Boolean)
    .filter((segment) => !/^\(.+\)$/.test(segment) && !segment.startsWith('@'))
    .map((segment) =>
      /^(?:\{[^}]+\}|:[A-Za-z0-9_]+|\[{1,2}(?:\.\.\.)?[^\]]+\]{1,2})$/.test(segment)
        ? '{}'
        : segment,
    );
  return `/${segments.join('/')}`.replace(/\/+$/g, '') || '/';
}

function lineOf(file: SourceFile, path: string): number {
  const candidates = [`"${path}"`, `'${path}'`, path];
  const index = candidates
    .map((candidate) => file.content.indexOf(candidate))
    .find((candidate) => candidate >= 0);
  return index === undefined ? 1 : file.content.slice(0, index).split('\n').length;
}

function commonPathScope(paths: string[]): string | null {
  if (!paths.length) return null;
  const segments = paths.map((path) => path.split('/').filter(Boolean));
  if (segments.length === 1) {
    const only = segments[0]!;
    const scope = only.length > 1 ? only.slice(0, -1) : only;
    return scope.length ? `/${scope.join('/')}` : null;
  }
  const common: string[] = [];
  for (let index = 0; index < segments[0]!.length; index++) {
    const segment = segments[0]![index]!;
    if (!segments.every((candidate) => candidate[index] === segment)) break;
    common.push(segment);
  }
  return common.length ? `/${common.join('/')}` : null;
}

function withinScope(path: string, scope: string): boolean {
  return path === scope || path.startsWith(`${scope}/`);
}

function declaredOperations(files: SourceFile[]): {
  specifications: ApiContractAnalysis['specifications'];
  operations: ApiContractOperation[];
  parseFailures: number;
  unresolvedPathReferences: number;
  truncated: boolean;
} {
  const specifications: ApiContractAnalysis['specifications'] = [];
  const operations: ApiContractOperation[] = [];
  let parseFailures = 0;
  let unresolvedPathReferences = 0;
  const candidates = files.filter(looksLikeSpecification);
  for (const file of candidates.slice(0, maximumSpecifications)) {
    const root = parseStructured(file);
    const version =
      typeof root?.openapi === 'string'
        ? root.openapi
        : typeof root?.swagger === 'string'
          ? root.swagger
          : null;
    const paths = object(root?.paths);
    if (!root || !version || !paths) {
      parseFailures++;
      continue;
    }
    let specificationOperations = 0;
    const specificationPaths: string[] = [];
    for (const [path, rawPath] of Object.entries(paths)) {
      if (operations.length >= maximumOperations) break;
      const pathItem = object(rawPath);
      if (!pathItem) continue;
      if (typeof pathItem.$ref === 'string') unresolvedPathReferences++;
      for (const [rawMethod, rawOperation] of Object.entries(pathItem)) {
        const method = rawMethod.toUpperCase();
        if (!supportedMethods.has(method) || !object(rawOperation)) continue;
        const operation = object(rawOperation)!;
        operations.push({
          id: `contract-op-${digest(`${file.path}:${method}:${path}`).slice(0, 16)}`,
          file: file.path,
          line: lineOf(file, path),
          path: path.slice(0, 500),
          normalizedPath: normalizeRoute(path).slice(0, 500),
          method,
          ...(typeof operation.operationId === 'string'
            ? { operationId: operation.operationId.slice(0, 300) }
            : {}),
          entrypointIds: [],
          status: 'declared-only',
        });
        specificationPaths.push(normalizeRoute(path).slice(0, 500));
        specificationOperations++;
      }
    }
    const pathScope = commonPathScope(specificationPaths);
    specifications.push({
      file: file.path,
      version: version.slice(0, 100),
      operations: specificationOperations,
      ...(pathScope ? { pathScope } : {}),
    });
  }
  return {
    specifications,
    operations,
    parseFailures,
    unresolvedPathReferences,
    truncated: candidates.length > maximumSpecifications || operations.length >= maximumOperations,
  };
}

function sourceOperations(profile: ProjectProfile): {
  operations: ApiSourceOperation[];
  routesWithoutMethods: string[];
  truncated: boolean;
} {
  const operations: ApiSourceOperation[] = [];
  const routesWithoutMethods = new Set<string>();
  for (const entrypoint of profile.entrypoints) {
    if (!routeEntrypointKinds.has(entrypoint.kind) || !entrypoint.route) continue;
    if (!entrypoint.methods.length) {
      routesWithoutMethods.add(entrypoint.id);
      continue;
    }
    for (const method of entrypoint.methods) {
      if (operations.length >= maximumSourceOperations) break;
      operations.push({
        id: `source-op-${digest(`${entrypoint.id}:${method}`).slice(0, 16)}`,
        entrypointId: entrypoint.id,
        ...(entrypoint.componentId ? { componentId: entrypoint.componentId } : {}),
        file: entrypoint.file,
        line: entrypoint.line,
        path: entrypoint.route.slice(0, 500),
        normalizedPath: normalizeRoute(entrypoint.route).slice(0, 500),
        method,
        contractOperationIds: [],
        status: 'outside-contract-scope',
      });
    }
  }
  return {
    operations,
    routesWithoutMethods: [...routesWithoutMethods].sort().slice(0, 500),
    truncated: operations.length >= maximumSourceOperations || routesWithoutMethods.size > 500,
  };
}

export function scanApiContract(
  snapshot: Snapshot,
  profile: ProjectProfile,
): { analysis: ApiContractAnalysis; run: ScannerRun } {
  const started = performance.now();
  const declared = declaredOperations(snapshot.files);
  const source = sourceOperations(profile);
  const sourceByKey = new Map<string, ApiSourceOperation[]>();
  for (const operation of source.operations) {
    const key = `${operation.method}:${operation.normalizedPath}`;
    sourceByKey.set(key, [...(sourceByKey.get(key) ?? []), operation]);
  }
  for (const operation of declared.operations) {
    const matches = sourceByKey.get(`${operation.method}:${operation.normalizedPath}`) ?? [];
    if (!matches.length) continue;
    operation.status = 'matched';
    operation.entrypointIds = [...new Set(matches.map((match) => match.entrypointId))].sort();
    for (const match of matches) {
      match.status = 'matched';
      match.contractOperationIds.push(operation.id);
    }
  }
  for (const operation of source.operations)
    operation.contractOperationIds = [...new Set(operation.contractOperationIds)].sort();
  const pathScopes = declared.specifications.flatMap((specification) =>
    specification.pathScope ? [specification.pathScope] : [],
  );
  for (const operation of source.operations)
    if (
      operation.status !== 'matched' &&
      pathScopes.some((scope) => withinScope(operation.normalizedPath, scope))
    )
      operation.status = 'source-only';

  const matchedOperations = declared.operations.filter(
    (operation) => operation.status === 'matched',
  ).length;
  const sourceOnly = source.operations.filter(
    (operation) => operation.status === 'source-only',
  ).length;
  const outsideContractScope = source.operations.filter(
    (operation) => operation.status === 'outside-contract-scope',
  ).length;
  const truncated =
    snapshot.truncated || profile.truncated || declared.truncated || source.truncated;
  const status: ApiContractAnalysis['status'] = !declared.specifications.length
    ? 'unsupported'
    : truncated ||
        declared.parseFailures > 0 ||
        declared.unresolvedPathReferences > 0 ||
        profile.status !== 'complete'
      ? 'partial'
      : 'complete';
  const analysis: ApiContractAnalysis = {
    schemaVersion: 1,
    version: '1.0.0',
    status,
    specifications: declared.specifications,
    declaredOperations: declared.operations,
    sourceOperations: source.operations,
    sourceRoutesWithoutMethods: source.routesWithoutMethods,
    summary: {
      specifications: declared.specifications.length,
      declaredOperations: declared.operations.length,
      matchedOperations,
      declaredOnly: declared.operations.length - matchedOperations,
      sourceOperations: source.operations.length,
      sourceOnly,
      outsideContractScope,
      sourceRoutesWithoutMethods: source.routesWithoutMethods.length,
    },
    parseFailures: declared.parseFailures,
    unresolvedPathReferences: declared.unresolvedPathReferences,
    truncated,
    limitations: [
      'OpenAPI and Swagger files are parsed as inert JSON or YAML; external references and executable generators are not loaded.',
      'Path parameters are compared structurally across OpenAPI, Next.js, and Express syntax.',
      'Unmatched source operations become candidates only inside the common static path scope inferred from each captured specification.',
      'A declared-only or source-only operation is a documentation consistency candidate, not proof that an endpoint is missing or exposed.',
      'Server base paths, rewrites, mounted routers, generated specifications, and runtime registration can prevent a static match.',
      'Routes with no statically observed HTTP method remain unverified and are not counted as source-only operations.',
    ],
  };
  return {
    analysis,
    run: {
      id: 'api-contract',
      name: 'API contract consistency',
      status: status === 'unsupported' ? 'skipped' : status === 'partial' ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: 0,
      detail:
        status === 'unsupported'
          ? 'No captured OpenAPI or Swagger specification was found.'
          : `Compared ${declared.operations.length} declared operation(s) with ${source.operations.length} statically mapped route operation(s): ${matchedOperations} matched, ${declared.operations.length - matchedOperations} declared only, ${sourceOnly} source only in contract scope, and ${outsideContractScope} outside contract scope.`,
      version: '1.0.0',
    },
  };
}
