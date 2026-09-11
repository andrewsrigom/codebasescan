import path from 'node:path';
import ts from 'typescript';
import { parseDocument } from 'yaml';
import type {
  ProjectDeclaredContext,
  ProjectFeature,
  ProjectSensitiveDataClass,
  ProjectVerificationContext,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';
import { isRuntimeSource } from '../security/paths.ts';

const maximumPatterns = 200;
const maximumWorkspaces = 50;
const maximumSaasAliases = 100;
const maximumWorkspacePackages = 200;
const maximumContextValues = 50;
const workspaceKeys = new Set([
  'entry',
  'project',
  'ignore',
  'ignoreFiles',
  'ignoreDependencies',
  'ignoreBinaries',
  'ignoreUnresolved',
  'ignoreIssues',
  'paths',
  'includeEntryExports',
  'ignoreExportsUsedInFile',
]);
const allowedIssueTypes = new Set([
  'files',
  'dependencies',
  'devDependencies',
  'unlisted',
  'exports',
  'types',
]);
const executableKnipConfig = /(?:^|\/)(?:\.knip|knip(?:\.config)?)\.[cm]?[jt]s$/i;
const executableCodebaseScanConfig = /(?:^|\/)codebasescan\.config\.[cm]?[jt]s$/i;

const saasVocabularyKeys = [
  'tenantKeys',
  'ownerKeys',
  'roleKeys',
  'billingKeys',
  'tokenKeys',
] as const;
const saasHelperKeys = [
  'authentication',
  'authorization',
  'validation',
  'resourceScope',
  'rateLimit',
  'idempotency',
  'csrf',
  'auditLog',
] as const;
const projectFeatures = new Set<ProjectFeature>([
  'authentication',
  'tenancy',
  'billing',
  'webhooks',
  'administration',
  'uploads',
]);
const sensitiveDataClasses = new Set<ProjectSensitiveDataClass>([
  'credentials',
  'personal',
  'financial',
  'health',
  'location',
  'communications',
  'files',
  'analytics',
]);
const contextKeys = new Set([
  'features',
  'roles',
  'sensitiveData',
  'storageBoundaries',
  'externalServices',
  'priorityPaths',
  'outOfScopePaths',
]);
const verificationKeys = new Set(['packageManager', 'testScripts', 'buildScripts']);

export interface SaasVocabulary {
  tenantKeys: string[];
  ownerKeys: string[];
  roleKeys: string[];
  billingKeys: string[];
  tokenKeys: string[];
}

export interface SaasHelpers {
  authentication: string[];
  authorization: string[];
  validation: string[];
  resourceScope: string[];
  rateLimit: string[];
  idempotency: string[];
  csrf: string[];
  auditLog: string[];
}

export interface TrustedSaasConfiguration {
  schemaVersion: 1;
  vocabulary: SaasVocabulary;
  helpers: SaasHelpers;
  expectedUnauthenticatedRoutes: string[];
  context?: ProjectDeclaredContext;
  verification?: ProjectVerificationContext;
}

export interface TrustedSaasConfigurationResult {
  config: TrustedSaasConfiguration;
  sources: string[];
  issues: string[];
}

export const defaultSaasConfiguration: TrustedSaasConfiguration = {
  schemaVersion: 1,
  vocabulary: {
    tenantKeys: [
      'tenant',
      'tenantId',
      'organization',
      'organizationId',
      'org',
      'orgId',
      'workspace',
      'workspaceId',
      'team',
      'teamId',
      'account',
      'accountId',
    ],
    ownerKeys: ['owner', 'ownerId', 'userId'],
    roleKeys: ['role', 'roles', 'permission', 'permissions', 'isAdmin'],
    billingKeys: [
      'amount',
      'amountCents',
      'unitAmount',
      'unit_amount',
      'price',
      'priceId',
      'price_id',
      'product',
      'productId',
      'product_id',
      'plan',
      'planId',
      'plan_id',
    ],
    tokenKeys: ['token', 'code', 'nonce', 'resetToken', 'inviteToken', 'verificationToken'],
  },
  helpers: {
    authentication: [],
    authorization: [],
    validation: [],
    resourceScope: [],
    rateLimit: ['rateLimit', 'checkRateLimit', 'enforceRateLimit', 'throttle'],
    idempotency: [
      'claimEvent',
      'ensureIdempotent',
      'checkIdempotency',
      'recordWebhookEvent',
      'upsertWebhookEvent',
    ],
    csrf: ['verifyCsrf', 'validateCsrf', 'checkOrigin', 'verifyOrigin'],
    auditLog: [],
  },
  expectedUnauthenticatedRoutes: [],
};

export interface TrustedKnipConfiguration {
  config: Record<string, unknown>;
  sources: string[];
  issues: string[];
}

export interface TypeScriptPathAlias {
  configFile: string;
  pattern: string;
  targets: string[];
}

export interface WorkspacePackageEntrypoint {
  name: string;
  manifest: string;
  file: string;
}

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseJsonc(file: SourceFile): Record<string, unknown> | null {
  const parsed = ts.parseConfigFileTextToJson(file.path, file.content);
  return parsed.error ? null : object(parsed.config);
}

function safePathPattern(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value || value.length > 300 || value.includes('\0'))
    return undefined;
  const normalized = value.replaceAll('\\', '/');
  const inspected = normalized.startsWith('!') ? normalized.slice(1) : normalized;
  if (
    !inspected ||
    inspected.startsWith('/') ||
    /^[a-z]:/i.test(inspected) ||
    inspected.includes('..')
  )
    return undefined;
  return normalized;
}

function safePackagePattern(value: unknown): string | undefined {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 214 &&
    !value.includes('..') &&
    !value.startsWith('/') &&
    /^[A-Za-z0-9@._*?/-]+$/.test(value)
    ? value
    : undefined;
}

function safeIdentifier(value: unknown): string | undefined {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 80 &&
    /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(value)
    ? value
    : undefined;
}

function safeContextLabel(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const label = value.trim();
  return label.length > 0 && label.length <= 80 && /^[A-Za-z0-9@._ /-]+$/.test(label)
    ? label
    : undefined;
}

function safeScriptName(value: unknown): string | undefined {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 80 &&
    /^[A-Za-z0-9:_-]+$/.test(value)
    ? value
    : undefined;
}

function boundedContextValues<T>(
  value: unknown,
  sanitize: (item: unknown) => T | undefined,
): T[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return [...new Set(value.slice(0, maximumContextValues).map(sanitize).filter(Boolean))] as T[];
}

function rejectedContextValues(
  value: unknown,
  sanitize: (item: unknown) => unknown | undefined,
): boolean {
  return (
    !Array.isArray(value) ||
    value.length > maximumContextValues ||
    value.some((item) => sanitize(item) === undefined)
  );
}

function safeRoutePattern(value: unknown): string | undefined {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    value.length > 300 ||
    value.includes('..') ||
    value.includes('\\') ||
    !/^\/[A-Za-z0-9_./:[\]-]*(?:\/\*)?$/.test(value)
  )
    return undefined;
  return value;
}

function boundedIdentifiers(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const values = [
    ...new Set(value.slice(0, maximumSaasAliases).map(safeIdentifier).filter(Boolean)),
  ];
  return values.length ? (values as string[]) : [];
}

function hasRejectedIdentifiers(value: unknown): boolean {
  return (
    !Array.isArray(value) ||
    value.length > maximumSaasAliases ||
    value.some((item) => safeIdentifier(item) === undefined)
  );
}

function mergeAliases(defaults: string[], configured: string[] | undefined): string[] {
  return [...new Set([...defaults, ...(configured ?? [])])];
}

function sanitizeProjectContext(value: unknown): ProjectDeclaredContext | undefined {
  const input = object(value);
  if (!input) return undefined;
  const feature = (item: unknown) =>
    typeof item === 'string' && projectFeatures.has(item as ProjectFeature)
      ? (item as ProjectFeature)
      : undefined;
  const dataClass = (item: unknown) =>
    typeof item === 'string' && sensitiveDataClasses.has(item as ProjectSensitiveDataClass)
      ? (item as ProjectSensitiveDataClass)
      : undefined;
  return {
    features: boundedContextValues(input.features, feature) ?? [],
    roles: boundedContextValues(input.roles, safeIdentifier) ?? [],
    sensitiveData: boundedContextValues(input.sensitiveData, dataClass) ?? [],
    storageBoundaries: boundedContextValues(input.storageBoundaries, safeContextLabel) ?? [],
    externalServices: boundedContextValues(input.externalServices, safeContextLabel) ?? [],
    priorityPaths: boundedContextValues(input.priorityPaths, safePathPattern) ?? [],
    outOfScopePaths: boundedContextValues(input.outOfScopePaths, safePathPattern) ?? [],
  };
}

function sanitizeVerification(value: unknown): ProjectVerificationContext | undefined {
  const input = object(value);
  if (!input || !['npm', 'pnpm', 'yarn'].includes(String(input.packageManager))) return undefined;
  return {
    packageManager: input.packageManager as ProjectVerificationContext['packageManager'],
    testScripts: boundedContextValues(input.testScripts, safeScriptName) ?? [],
    buildScripts: boundedContextValues(input.buildScripts, safeScriptName) ?? [],
  };
}

function saasHasRejectedSettings(value: unknown): boolean {
  const input = object(value);
  if (!input) return true;
  if (
    Object.keys(input).some(
      (key) =>
        key !== '$schema' &&
        key !== 'schemaVersion' &&
        key !== 'vocabulary' &&
        key !== 'helpers' &&
        key !== 'expectedUnauthenticatedRoutes' &&
        key !== 'context' &&
        key !== 'verification',
    )
  )
    return true;
  if (input.schemaVersion !== 1) return true;
  const vocabulary = object(input.vocabulary);
  if (
    input.vocabulary !== undefined &&
    (!vocabulary ||
      Object.keys(vocabulary).some(
        (key) => !saasVocabularyKeys.includes(key as (typeof saasVocabularyKeys)[number]),
      ) ||
      Object.values(vocabulary).some(hasRejectedIdentifiers))
  )
    return true;
  const helpers = object(input.helpers);
  if (
    input.helpers !== undefined &&
    (!helpers ||
      Object.keys(helpers).some(
        (key) => !saasHelperKeys.includes(key as (typeof saasHelperKeys)[number]),
      ) ||
      Object.values(helpers).some(hasRejectedIdentifiers))
  )
    return true;
  if (
    input.expectedUnauthenticatedRoutes !== undefined &&
    (!Array.isArray(input.expectedUnauthenticatedRoutes) ||
      input.expectedUnauthenticatedRoutes.length > maximumSaasAliases ||
      input.expectedUnauthenticatedRoutes.some((route) => safeRoutePattern(route) === undefined))
  )
    return true;
  const context = object(input.context);
  if (input.context !== undefined) {
    if (!context || Object.keys(context).some((key) => !contextKeys.has(key))) return true;
    if (
      context.features !== undefined &&
      rejectedContextValues(context.features, (item) =>
        typeof item === 'string' && projectFeatures.has(item as ProjectFeature)
          ? (item as ProjectFeature)
          : undefined,
      )
    )
      return true;
    if (context.roles !== undefined && rejectedContextValues(context.roles, safeIdentifier))
      return true;
    if (
      context.sensitiveData !== undefined &&
      rejectedContextValues(context.sensitiveData, (item) =>
        typeof item === 'string' && sensitiveDataClasses.has(item as ProjectSensitiveDataClass)
          ? (item as ProjectSensitiveDataClass)
          : undefined,
      )
    )
      return true;
    for (const key of ['storageBoundaries', 'externalServices'] as const)
      if (context[key] !== undefined && rejectedContextValues(context[key], safeContextLabel))
        return true;
    for (const key of ['priorityPaths', 'outOfScopePaths'] as const)
      if (context[key] !== undefined && rejectedContextValues(context[key], safePathPattern))
        return true;
  }
  const verification = object(input.verification);
  if (input.verification !== undefined) {
    if (!verification || Object.keys(verification).some((key) => !verificationKeys.has(key)))
      return true;
    if (!['npm', 'pnpm', 'yarn'].includes(String(verification.packageManager))) return true;
    for (const key of ['testScripts', 'buildScripts'] as const)
      if (
        verification[key] !== undefined &&
        rejectedContextValues(verification[key], safeScriptName)
      )
        return true;
  }
  return false;
}

function sanitizeSaasConfiguration(value: unknown): TrustedSaasConfiguration {
  const input = object(value) ?? {};
  const vocabulary = object(input.vocabulary) ?? {};
  const helpers = object(input.helpers) ?? {};
  const context = sanitizeProjectContext(input.context);
  const verification = sanitizeVerification(input.verification);
  return {
    schemaVersion: 1,
    vocabulary: Object.fromEntries(
      saasVocabularyKeys.map((key) => [
        key,
        mergeAliases(defaultSaasConfiguration.vocabulary[key], boundedIdentifiers(vocabulary[key])),
      ]),
    ) as unknown as SaasVocabulary,
    helpers: Object.fromEntries(
      saasHelperKeys.map((key) => [
        key,
        mergeAliases(defaultSaasConfiguration.helpers[key], boundedIdentifiers(helpers[key])),
      ]),
    ) as unknown as SaasHelpers,
    expectedUnauthenticatedRoutes: [
      ...new Set(
        (Array.isArray(input.expectedUnauthenticatedRoutes)
          ? input.expectedUnauthenticatedRoutes.slice(0, maximumSaasAliases)
          : []
        )
          .map(safeRoutePattern)
          .filter(Boolean),
      ),
    ] as string[],
    ...(context ? { context } : {}),
    ...(verification ? { verification } : {}),
  };
}

function safeAliasPath(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value || value.length > 300 || value.includes('\0'))
    return undefined;
  const normalized = value.replaceAll('\\', '/');
  return normalized.startsWith('/') || /^[a-z]:/i.test(normalized) ? undefined : normalized;
}

function safeAliasPattern(value: unknown): string | undefined {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 300 &&
    !value.includes('..') &&
    value.split('*').length <= 2 &&
    /^[A-Za-z0-9@#~_./*-]+$/.test(value)
    ? value
    : undefined;
}

function sanitizePaths(value: unknown): Record<string, string[]> | undefined {
  const input = object(value);
  if (!input) return undefined;
  const output: Record<string, string[]> = {};
  for (const [rawPattern, rawTargets] of Object.entries(input).slice(0, maximumPatterns)) {
    const pattern = safeAliasPattern(rawPattern);
    const targets = strings(rawTargets, safePathPattern);
    if (pattern && targets) output[pattern] = targets;
  }
  return Object.keys(output).length ? output : undefined;
}

function rejectedList(value: unknown, sanitize: (item: unknown) => string | undefined): boolean {
  return (
    !Array.isArray(value) ||
    value.length > maximumPatterns ||
    value.some((item) => sanitize(item) === undefined)
  );
}

function workspaceHasRejectedSettings(value: unknown): boolean {
  const input = object(value);
  if (!input) return true;
  if (Object.keys(input).some((key) => !workspaceKeys.has(key))) return true;
  for (const key of ['entry', 'project', 'ignore', 'ignoreFiles'] as const)
    if (input[key] !== undefined && rejectedList(input[key], safePathPattern)) return true;
  for (const key of ['ignoreDependencies', 'ignoreBinaries', 'ignoreUnresolved'] as const)
    if (input[key] !== undefined && rejectedList(input[key], safePackagePattern)) return true;
  for (const key of ['includeEntryExports', 'ignoreExportsUsedInFile'] as const)
    if (input[key] !== undefined && typeof input[key] !== 'boolean') return true;
  if (input.ignoreIssues !== undefined) {
    const ignoreIssues = object(input.ignoreIssues);
    if (!ignoreIssues || Object.keys(ignoreIssues).length > maximumPatterns) return true;
    for (const [pattern, types] of Object.entries(ignoreIssues))
      if (
        !safePathPattern(pattern) ||
        !Array.isArray(types) ||
        types.some((item) => typeof item !== 'string' || !allowedIssueTypes.has(item))
      )
        return true;
  }
  if (input.paths !== undefined) {
    const paths = object(input.paths);
    if (!paths || Object.keys(paths).length > maximumPatterns) return true;
    for (const [pattern, targets] of Object.entries(paths))
      if (!safeAliasPattern(pattern) || rejectedList(targets, safePathPattern)) return true;
  }
  return false;
}

function knipHasRejectedSettings(value: unknown): boolean {
  const input = object(value);
  if (!input) return true;
  if (
    Object.keys(input).some(
      (key) => key !== '$schema' && key !== 'workspaces' && !workspaceKeys.has(key),
    )
  )
    return true;
  const rootSettings = Object.fromEntries(
    Object.entries(input).filter(([key]) => workspaceKeys.has(key)),
  );
  if (workspaceHasRejectedSettings(rootSettings)) return true;
  if (input.workspaces === undefined) return false;
  const workspaces = object(input.workspaces);
  if (!workspaces || Object.keys(workspaces).length > maximumWorkspaces) return true;
  return Object.entries(workspaces).some(
    ([pattern, config]) => !safePathPattern(pattern) || workspaceHasRejectedSettings(config),
  );
}

function strings(
  value: unknown,
  sanitize: (item: unknown) => string | undefined,
): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const items = [
    ...new Set(value.slice(0, maximumPatterns).map(sanitize).filter(Boolean)),
  ] as string[];
  return items.length ? items : undefined;
}

function sanitizeIgnoreIssues(value: unknown): Record<string, string[]> | undefined {
  const input = object(value);
  if (!input) return undefined;
  const output: Record<string, string[]> = {};
  for (const [rawPattern, rawTypes] of Object.entries(input).slice(0, maximumPatterns)) {
    const pattern = safePathPattern(rawPattern);
    if (!pattern || !Array.isArray(rawTypes)) continue;
    const types = [
      ...new Set(
        rawTypes.filter((item): item is string =>
          typeof item === 'string' ? allowedIssueTypes.has(item) : false,
        ),
      ),
    ];
    if (types.length) output[pattern] = types;
  }
  return Object.keys(output).length ? output : undefined;
}

function sanitizeWorkspace(value: unknown): Record<string, unknown> {
  const input = object(value) ?? {};
  const output: Record<string, unknown> = {};
  for (const key of ['entry', 'project', 'ignore', 'ignoreFiles'] as const) {
    const items = strings(input[key], safePathPattern);
    if (items) output[key] = items;
  }
  for (const key of ['ignoreDependencies', 'ignoreBinaries', 'ignoreUnresolved'] as const) {
    const items = strings(input[key], safePackagePattern);
    if (items) output[key] = items;
  }
  const ignoreIssues = sanitizeIgnoreIssues(input.ignoreIssues);
  if (ignoreIssues) output.ignoreIssues = ignoreIssues;
  const paths = sanitizePaths(input.paths);
  if (paths) output.paths = paths;
  if (typeof input.includeEntryExports === 'boolean')
    output.includeEntryExports = input.includeEntryExports;
  if (typeof input.ignoreExportsUsedInFile === 'boolean')
    output.ignoreExportsUsedInFile = input.ignoreExportsUsedInFile;
  return output;
}

function sanitizeKnipRoot(value: unknown): Record<string, unknown> {
  const input = object(value) ?? {};
  const output = sanitizeWorkspace(input);
  const rawWorkspaces = object(input.workspaces);
  if (rawWorkspaces) {
    const workspaces: Record<string, unknown> = {};
    for (const [rawPattern, rawConfig] of Object.entries(rawWorkspaces).slice(
      0,
      maximumWorkspaces,
    )) {
      const pattern = safePathPattern(rawPattern);
      if (pattern && object(rawConfig)) workspaces[pattern] = sanitizeWorkspace(rawConfig);
    }
    if (Object.keys(workspaces).length) output.workspaces = workspaces;
  }
  return output;
}

export function declarativeKnipConfiguration(snapshot: Snapshot): TrustedKnipConfiguration {
  const sources: string[] = [];
  const issues: string[] = [];
  const candidates = ['knip.json', '.knip.json', 'knip.jsonc', '.knip.jsonc'];
  for (const name of candidates) {
    const file = snapshot.files.find((item) => item.path === name && isRuntimeSource(item));
    if (!file) continue;
    const parsed = parseJsonc(file);
    if (!parsed) {
      issues.push(`${name} could not be parsed as declarative JSON.`);
      return { config: {}, sources, issues };
    }
    sources.push(name);
    if (knipHasRejectedSettings(parsed))
      issues.push(`${name} contains unsupported or unsafe settings that were ignored.`);
    return { config: sanitizeKnipRoot(parsed), sources, issues };
  }
  const manifest = snapshot.files.find(
    (item) => item.path === 'package.json' && isRuntimeSource(item),
  );
  if (manifest) {
    const parsed = parseJsonc(manifest);
    if (parsed?.knip && object(parsed.knip)) {
      sources.push('package.json#knip');
      if (knipHasRejectedSettings(parsed.knip))
        issues.push('package.json#knip contains unsupported or unsafe settings that were ignored.');
      return { config: sanitizeKnipRoot(parsed.knip), sources, issues };
    }
  }
  if (snapshot.files.some((file) => isRuntimeSource(file) && executableKnipConfig.test(file.path)))
    issues.push('Executable Knip configuration was ignored. Use knip.json for safe import.');
  return { config: {}, sources, issues };
}

function retainDeclaredVerificationScripts(
  snapshot: Snapshot,
  config: TrustedSaasConfiguration,
  issues: string[],
): TrustedSaasConfiguration {
  if (!config.verification) return config;
  const manifest = snapshot.files.find(
    (file) => file.path === 'package.json' && isRuntimeSource(file),
  );
  const scripts = object(manifest ? parseJsonc(manifest)?.scripts : undefined) ?? {};
  const retain = (names: string[]) => names.filter((name) => typeof scripts[name] === 'string');
  const testScripts = retain(config.verification.testScripts);
  const buildScripts = retain(config.verification.buildScripts);
  const omitted =
    config.verification.testScripts.length +
    config.verification.buildScripts.length -
    testScripts.length -
    buildScripts.length;
  if (omitted)
    issues.push(
      `${omitted} verification script name(s) were ignored because the root package.json does not declare them.`,
    );
  return {
    ...config,
    verification: { ...config.verification, testScripts, buildScripts },
  };
}

export function declarativeSaasConfiguration(snapshot: Snapshot): TrustedSaasConfigurationResult {
  const sources: string[] = [];
  const issues: string[] = [];
  const candidates = ['codebasescan.config.json', 'codebasescan.config.jsonc'];
  for (const name of candidates) {
    const file = snapshot.files.find((item) => item.path === name && isRuntimeSource(item));
    if (!file) continue;
    const parsed = parseJsonc(file);
    if (!parsed) {
      issues.push(`${name} could not be parsed as declarative JSON.`);
      return { config: sanitizeSaasConfiguration({}), sources, issues };
    }
    sources.push(name);
    if (saasHasRejectedSettings(parsed))
      issues.push(`${name} contains unsupported or unsafe settings that were ignored.`);
    const config = retainDeclaredVerificationScripts(
      snapshot,
      sanitizeSaasConfiguration(parsed),
      issues,
    );
    return { config, sources, issues };
  }
  if (
    snapshot.files.some(
      (file) => isRuntimeSource(file) && executableCodebaseScanConfig.test(file.path),
    )
  )
    issues.push(
      'Executable CodebaseScan configuration was ignored. Use codebasescan.config.json for safe import.',
    );
  return { config: sanitizeSaasConfiguration({}), sources, issues };
}

function workspacePatternsFromManifest(file: SourceFile): string[] {
  const parsed = parseJsonc(file);
  const workspaces = parsed?.workspaces;
  if (Array.isArray(workspaces)) return strings(workspaces, safePathPattern) ?? [];
  return strings(object(workspaces)?.packages, safePathPattern) ?? [];
}

export function declarativeWorkspacePatterns(snapshot: Snapshot): string[] {
  const patterns = new Set<string>();
  const manifest = snapshot.files.find(
    (file) => file.path === 'package.json' && isRuntimeSource(file),
  );
  if (manifest)
    for (const pattern of workspacePatternsFromManifest(manifest)) patterns.add(pattern);
  const pnpm = snapshot.files.find(
    (file) => file.path === 'pnpm-workspace.yaml' && isRuntimeSource(file),
  );
  if (pnpm) {
    try {
      const document = parseDocument(pnpm.content, { schema: 'core' });
      const root = document.errors.length ? null : object(document.toJS({ maxAliasCount: 20 }));
      for (const pattern of strings(root?.packages, safePathPattern) ?? []) patterns.add(pattern);
    } catch {
      // Invalid workspace files are ignored; no external file is loaded.
    }
  }
  return [...patterns].sort();
}

function packageExportTarget(value: unknown, depth = 0): string | undefined {
  if (depth > 3) return undefined;
  if (typeof value === 'string') return safeAliasPath(value);
  const input = object(value);
  if (!input) return undefined;
  for (const key of ['import', 'node', 'default', 'require', 'types']) {
    const target = packageExportTarget(input[key], depth + 1);
    if (target) return target;
  }
  return undefined;
}

function capturedSourceTarget(base: string, paths: Set<string>): string | undefined {
  const candidates = new Set<string>([base]);
  const sourceExtension = /(?:\.d)?\.[cm]?[jt]sx?$/i.exec(base)?.[0];
  const stem = sourceExtension ? base.slice(0, -sourceExtension.length) : base;
  for (const candidate of ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']) {
    candidates.add(`${stem}${candidate}`);
    if (!sourceExtension) candidates.add(`${base}/index${candidate}`);
  }
  return [...candidates].find((candidate) => paths.has(candidate));
}

function capturedPackageSourceTarget(
  base: string,
  directory: string,
  paths: Set<string>,
): string | undefined {
  const direct = capturedSourceTarget(base, paths);
  if (direct) return direct;
  const relative = directory ? base.slice(directory.length + 1) : base;
  const emitted = /^(?:dist|build|lib|out)\/(.+)$/.exec(relative)?.[1];
  if (!emitted) return undefined;
  const candidates = [
    path.posix.join(directory, emitted),
    ...(emitted.startsWith('src/') ? [] : [path.posix.join(directory, 'src', emitted)]),
  ];
  return candidates
    .map((candidate) => capturedSourceTarget(candidate, paths))
    .find((candidate): candidate is string => Boolean(candidate));
}

export function declarativeWorkspacePackageEntrypoints(snapshot: Snapshot): {
  entries: WorkspacePackageEntrypoint[];
  issues: string[];
} {
  const entries: WorkspacePackageEntrypoint[] = [];
  const issues: string[] = [];
  const sourcePaths = new Set(snapshot.files.map((file) => file.path));
  const manifests = snapshot.files
    .filter((file) => isRuntimeSource(file) && /(?:^|\/)package\.json$/.test(file.path))
    .slice(0, maximumWorkspacePackages);
  for (const manifest of manifests) {
    const parsed = parseJsonc(manifest);
    const name = safePackagePattern(parsed?.name);
    if (!parsed || !name || /[*?]/.test(name)) continue;
    const directory =
      path.posix.dirname(manifest.path) === '.' ? '' : path.posix.dirname(manifest.path);
    const rawExports = parsed.exports;
    const exportsObject = object(rawExports);
    const target =
      packageExportTarget(
        exportsObject && Object.hasOwn(exportsObject, '.') ? exportsObject['.'] : rawExports,
      ) ??
      packageExportTarget(parsed.module) ??
      packageExportTarget(parsed.main) ??
      packageExportTarget(parsed.types);
    const rawBases = target ? [target] : ['./src/index', './index'];
    const resolved = rawBases.flatMap((rawBase) => {
      const normalizedTarget = rawBase.replace(/^\.\//, '');
      if (!normalizedTarget || normalizedTarget.includes('..')) return [];
      const base = path.posix.normalize(path.posix.join(directory, normalizedTarget));
      const contained = directory ? base.startsWith(`${directory}/`) : !base.startsWith('../');
      if (!contained) return [];
      const captured = capturedPackageSourceTarget(base, directory, sourcePaths);
      return captured ? [captured] : [];
    })[0];
    if (resolved) entries.push({ name, manifest: manifest.path, file: resolved });
    else if (target)
      issues.push(`${manifest.path} declares a package entry point outside captured source.`);
  }
  return {
    entries: [
      ...new Map(
        entries
          .sort((left, right) => left.name.localeCompare(right.name))
          .map((entry) => [entry.name, entry]),
      ).values(),
    ],
    issues: issues.slice(0, 100),
  };
}

export function sanitizedManifest(
  file: SourceFile,
  workspacePatterns: string[] = [],
): Record<string, unknown> {
  const parsed = parseJsonc(file) ?? {};
  const output: Record<string, unknown> = {
    name:
      typeof parsed.name === 'string' ? parsed.name.slice(0, 214) : 'codebasescan-staged-project',
    private: true,
  };
  if (parsed.type === 'module') output.type = 'module';
  for (const key of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ] as const) {
    const section = object(parsed[key]);
    if (!section) continue;
    const safe = Object.fromEntries(
      Object.entries(section)
        .slice(0, 2000)
        .filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
    );
    if (Object.keys(safe).length) output[key] = safe;
  }
  if (file.path === 'package.json' && workspacePatterns.length)
    output.workspaces = workspacePatterns;
  return output;
}

export function typeScriptPathAliases(snapshot: Snapshot): {
  aliases: TypeScriptPathAlias[];
  issues: string[];
} {
  const aliases: TypeScriptPathAlias[] = [];
  const issues: string[] = [];
  const configs = snapshot.files.filter(
    (file) => isRuntimeSource(file) && /(?:^|\/)tsconfig(?:\.[^/]+)?\.jsonc?$/.test(file.path),
  );
  for (const file of configs.slice(0, 50)) {
    const parsed = parseJsonc(file);
    if (!parsed) {
      issues.push(`${file.path} could not be parsed as JSON.`);
      continue;
    }
    const compilerOptions = object(parsed.compilerOptions);
    const paths = object(compilerOptions?.paths);
    if (!paths) continue;
    const directory = path.posix.dirname(file.path) === '.' ? '' : path.posix.dirname(file.path);
    const baseUrl = safeAliasPath(compilerOptions?.baseUrl) ?? '';
    for (const [pattern, rawTargets] of Object.entries(paths).slice(0, maximumPatterns)) {
      if (pattern.split('*').length > 2 || !Array.isArray(rawTargets)) {
        issues.push(`${file.path} contains an unsupported path alias for ${pattern}.`);
        continue;
      }
      const targets = rawTargets.flatMap((rawTarget) => {
        const target = safeAliasPath(rawTarget);
        if (!target || target.split('*').length > 2) return [];
        const resolved = path.posix.normalize(path.posix.join(directory, baseUrl, target));
        return resolved === '..' || resolved.startsWith('../') ? [] : [resolved];
      });
      if (targets.length) aliases.push({ configFile: file.path, pattern, targets });
      if (targets.length !== rawTargets.length)
        issues.push(`${file.path} contains an unsafe path target for ${pattern}.`);
    }
    if (Object.keys(paths).length > maximumPatterns)
      issues.push(`${file.path} path aliases were limited to ${maximumPatterns}.`);
  }
  return { aliases: aliases.slice(0, maximumPatterns), issues };
}
