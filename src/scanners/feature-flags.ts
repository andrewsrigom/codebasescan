import ts from 'typescript';
import { digest } from '../domain/findings.ts';
import type {
  FeatureFlagAnalysis,
  FeatureFlagContract,
  FeatureFlagDeclaration,
  FeatureFlagLiteral,
  FeatureFlagUsage,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';

const sourcePattern = /\.(?:[cm]?[jt]sx?)$/i;
const definitionNamePattern = /(?:feature.*flags?|runtime.*flags?|flags?.*definitions?)/i;
const flagCallPattern =
  /(?:^|\.)(?:isFeatureEnabled|isFeatureFlagEnabled|hasFeature|hasFeatureFlag|evaluate(?:Runtime)?FeatureFlag|resolve(?:Runtime)?FeatureFlagEvaluation|get(?:Known)?RuntimeFlagDefinitionByKey|getFeatureFlag|getFlagValue|useFeatureFlag|checkFeatureFlag|variation|checkGate|getFeatureValue|isOn|isOff)$/i;
const providerMethodPattern =
  /(?:^|\.)(?:variation|isEnabled|isFeatureEnabled|checkGate|getFeatureValue|hasFeature|getValue)$/i;
const providerPackages = new Map([
  ['launchdarkly', 'LaunchDarkly'],
  ['posthog', 'PostHog'],
  ['unleash', 'Unleash'],
  ['growthbook', 'GrowthBook'],
  ['statsig', 'Statsig'],
  ['splitio', 'Split'],
  ['flagsmith', 'Flagsmith'],
  ['configcat', 'ConfigCat'],
  ['@vercel/flags', 'Vercel Flags'],
]);
const defaultProperties = new Set([
  'default',
  'defaultvalue',
  'defaultstatus',
  'defaultvariant',
  'fallback',
  'fallbackvalue',
]);
const keyProperties = new Set(['key', 'flagkey', 'featurekey', 'name']);
const maximumDeclarations = 2_000;
const maximumUsages = 5_000;

function stableId(...parts: string[]): string {
  return digest(parts.join(':')).slice(0, 20);
}

function normalizeKey(value: string): string {
  return value.trim().toLowerCase().slice(0, 300);
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

function lineOfText(file: SourceFile, value: string): number {
  const quoted = [`"${value}"`, `'${value}'`];
  const index = quoted
    .map((candidate) => file.content.indexOf(candidate))
    .find((item) => item >= 0);
  return index === undefined ? 1 : file.content.slice(0, index).split('\n').length;
}

function propertyName(node: ts.PropertyName | ts.BindingName | undefined): string | null {
  if (!node) return null;
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node))
    return node.text;
  return null;
}

function primitive(value: unknown): FeatureFlagLiteral | null {
  let kind: FeatureFlagLiteral['kind'];
  let raw: string;
  if (value === null) {
    kind = 'null';
    raw = 'null';
  } else if (typeof value === 'boolean') {
    kind = 'boolean';
    raw = String(value);
  } else if (typeof value === 'number' && Number.isFinite(value)) {
    kind = 'number';
    raw = String(value);
  } else if (typeof value === 'string') {
    kind = 'string';
    raw = value.slice(0, 1_000);
  } else return null;
  const safeDisplay =
    kind === 'boolean' || kind === 'number' || /^(?:enabled|disabled|on|off|control)$/i.test(raw)
      ? raw.slice(0, 100)
      : undefined;
  return {
    kind,
    fingerprint: digest(`${kind}:${raw}`),
    ...(safeDisplay ? { display: safeDisplay } : {}),
  };
}

function primitiveExpression(node: ts.Expression): FeatureFlagLiteral | null {
  if (node.kind === ts.SyntaxKind.TrueKeyword) return primitive(true);
  if (node.kind === ts.SyntaxKind.FalseKeyword) return primitive(false);
  if (node.kind === ts.SyntaxKind.NullKeyword) return primitive(null);
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))
    return primitive(node.text);
  if (ts.isNumericLiteral(node)) return primitive(Number(node.text));
  return null;
}

function stringExpression(node: ts.Expression): string | null {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : null;
}

function objectProperty(
  object: ts.ObjectLiteralExpression,
  names: Set<string>,
): ts.PropertyAssignment | undefined {
  return object.properties.find(
    (property): property is ts.PropertyAssignment =>
      ts.isPropertyAssignment(property) &&
      names.has((propertyName(property.name) ?? '').toLowerCase()),
  );
}

function jsonDeclarations(file: SourceFile): FeatureFlagDeclaration[] {
  if (!file.path.toLowerCase().endsWith('.json') || file.scope !== 'runtime') return [];
  let root: unknown;
  try {
    root = JSON.parse(file.content);
  } catch {
    return [];
  }
  const declarations: FeatureFlagDeclaration[] = [];
  const visit = (value: unknown, parentKey = ''): void => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    const record = value as Record<string, unknown>;
    const isFlagMap = /^(?:featureflags?|feature_flags?)$/i.test(parentKey);
    if (isFlagMap) {
      for (const [key, defaultValue] of Object.entries(record)) {
        const literal = primitive(defaultValue);
        if (!literal || declarations.length >= maximumDeclarations) continue;
        declarations.push({
          id: `flag-declaration-${stableId(file.path, key, literal.fingerprint)}`,
          key: key.slice(0, 300),
          normalizedKey: normalizeKey(key),
          file: file.path,
          line: lineOfText(file, key),
          source: 'json-feature-flags',
          default: literal,
        });
      }
      return;
    }
    for (const [key, child] of Object.entries(record)) visit(child, key);
  };
  visit(root);
  return declarations;
}

function typescriptDeclarations(file: SourceFile, source: ts.SourceFile): FeatureFlagDeclaration[] {
  const declarations: FeatureFlagDeclaration[] = [];
  const add = (key: string, node: ts.Node, defaultValue: FeatureFlagLiteral | null) => {
    if (!normalizeKey(key) || declarations.length >= maximumDeclarations) return;
    declarations.push({
      id: `flag-declaration-${stableId(file.path, String(lineOf(source, node)), key)}`,
      key: key.slice(0, 300),
      normalizedKey: normalizeKey(key),
      file: file.path,
      line: lineOf(source, node),
      source: 'typescript-definition',
      ...(defaultValue ? { default: defaultValue } : {}),
    });
  };
  const definitionObject = (object: ts.ObjectLiteralExpression) => {
    const keyProperty = objectProperty(object, keyProperties);
    if (!keyProperty) return;
    const key = stringExpression(keyProperty.initializer);
    if (!key) return;
    const defaultProperty = objectProperty(object, defaultProperties);
    add(
      key,
      keyProperty.initializer,
      defaultProperty ? primitiveExpression(defaultProperty.initializer) : null,
    );
  };
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node)) {
      const name = propertyName(node.name);
      if (name && definitionNamePattern.test(name) && node.initializer) {
        let initializer: ts.Expression = node.initializer;
        while (ts.isAsExpression(initializer) || ts.isSatisfiesExpression(initializer))
          initializer = initializer.expression;
        if (ts.isArrayLiteralExpression(initializer))
          for (const element of initializer.elements)
            if (ts.isObjectLiteralExpression(element)) definitionObject(element);
        if (ts.isObjectLiteralExpression(initializer))
          for (const property of initializer.properties) {
            if (!ts.isPropertyAssignment(property)) continue;
            const key = propertyName(property.name);
            const value = key ? primitiveExpression(property.initializer) : null;
            if (key && value) add(key, property.name, value);
          }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return declarations;
}

function calleeText(source: ts.SourceFile, call: ts.CallExpression): string {
  return call.expression.getText(source).slice(0, 300);
}

function providerNames(snapshot: Snapshot): Set<string> {
  const providers = new Set<string>();
  for (const file of snapshot.files) {
    if (file.scope !== 'runtime') continue;
    const lower = file.content.toLowerCase();
    for (const [needle, label] of providerPackages)
      if (lower.includes(needle)) providers.add(label);
  }
  return providers;
}

function recognizedCall(callee: string, providersPresent: boolean): boolean {
  return flagCallPattern.test(callee) || (providersPresent && providerMethodPattern.test(callee));
}

function callKey(call: ts.CallExpression): string | null {
  const first = call.arguments[0];
  if (!first) return null;
  const direct = stringExpression(first);
  if (direct) return direct;
  if (!ts.isObjectLiteralExpression(first)) return null;
  const property = objectProperty(first, keyProperties);
  return property ? stringExpression(property.initializer) : null;
}

function callDefault(call: ts.CallExpression, callee: string): FeatureFlagLiteral | null {
  const first = call.arguments[0];
  if (first && ts.isObjectLiteralExpression(first)) {
    const property = objectProperty(first, defaultProperties);
    if (property) return primitiveExpression(property.initializer);
  }
  const candidates = /variation$/i.test(callee)
    ? [call.arguments[2], call.arguments[1]]
    : [call.arguments[1]];
  for (const candidate of candidates)
    if (candidate) {
      const value = primitiveExpression(candidate);
      if (value) return value;
    }
  return null;
}

function callContext(call: ts.CallExpression): FeatureFlagUsage['context'] {
  let node: ts.Node = call;
  while (
    ts.isAwaitExpression(node.parent) ||
    ts.isParenthesizedExpression(node.parent) ||
    ts.isPrefixUnaryExpression(node.parent)
  )
    node = node.parent;
  return ts.isIfStatement(node.parent) ||
    ts.isConditionalExpression(node.parent) ||
    (ts.isBinaryExpression(node.parent) &&
      [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken].includes(
        node.parent.operatorToken.kind,
      ))
    ? 'guard'
    : 'read';
}

function sourceUsages(
  snapshot: Snapshot,
  profile: ProjectProfile,
  providersPresent: boolean,
): {
  usages: FeatureFlagUsage[];
  declarations: FeatureFlagDeclaration[];
  parseFailures: number;
  truncated: boolean;
} {
  const usages: FeatureFlagUsage[] = [];
  const declarations: FeatureFlagDeclaration[] = [];
  const componentByFile = new Map<string, string>();
  for (const symbol of profile.symbols)
    if (symbol.componentId) componentByFile.set(symbol.file, symbol.componentId);
  let parseFailures = 0;
  let truncated = false;
  for (const file of snapshot.files) {
    if (file.scope !== 'runtime' || !sourcePattern.test(file.path)) continue;
    const source = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
      .parseDiagnostics;
    if (diagnostics?.length) {
      if (definitionNamePattern.test(file.content) || /feature.*flag/i.test(file.content))
        parseFailures++;
      continue;
    }
    declarations.push(...typescriptDeclarations(file, source));
    const visit = (node: ts.Node): void => {
      if (usages.length >= maximumUsages) {
        truncated = true;
        return;
      }
      if (ts.isCallExpression(node)) {
        const callee = calleeText(source, node);
        if (recognizedCall(callee, providersPresent)) {
          const key = callKey(node);
          const line = lineOf(source, node);
          const defaultValue = callDefault(node, callee);
          usages.push({
            id: `flag-usage-${stableId(file.path, String(line), callee, key ?? 'dynamic')}`,
            file: file.path,
            line,
            callee,
            context: callContext(node),
            ...(key ? { key: key.slice(0, 300), normalizedKey: normalizeKey(key) } : {}),
            ...(componentByFile.get(file.path)
              ? { componentId: componentByFile.get(file.path) }
              : {}),
            ...(defaultValue ? { default: defaultValue } : {}),
            declarationIds: [],
            status: key ? 'usage-only' : 'dynamic',
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return { usages, declarations, parseFailures, truncated };
}

function defaultConflict(
  declarations: FeatureFlagDeclaration[],
  usages: FeatureFlagUsage[],
): boolean {
  const sourceDefaults = new Set(
    usages.flatMap((usage) => (usage.default ? [usage.default.fingerprint] : [])),
  );
  if (sourceDefaults.size > 1) return true;
  const declaredDefaults = new Set(
    declarations.flatMap((declaration) =>
      declaration.default ? [declaration.default.fingerprint] : [],
    ),
  );
  return (
    sourceDefaults.size === 1 &&
    declaredDefaults.size === 1 &&
    [...sourceDefaults][0] !== [...declaredDefaults][0]
  );
}

export function scanFeatureFlags(
  snapshot: Snapshot,
  profile: ProjectProfile,
): { analysis: FeatureFlagAnalysis; run: ScannerRun } {
  const started = performance.now();
  const providers = providerNames(snapshot);
  const json = snapshot.files.flatMap(jsonDeclarations).slice(0, maximumDeclarations);
  const source = sourceUsages(snapshot, profile, providers.size > 0);
  const declarations = [...json, ...source.declarations]
    .slice(0, maximumDeclarations)
    .sort((left, right) => left.file.localeCompare(right.file) || left.line - right.line);
  const declarationsByKey = new Map<string, FeatureFlagDeclaration[]>();
  for (const declaration of declarations) {
    const existing = declarationsByKey.get(declaration.normalizedKey) ?? [];
    existing.push(declaration);
    declarationsByKey.set(declaration.normalizedKey, existing);
  }
  for (const usage of source.usages) {
    if (!usage.normalizedKey) continue;
    const matches = declarationsByKey.get(usage.normalizedKey) ?? [];
    usage.declarationIds = matches.map((declaration) => declaration.id).sort();
    usage.status = matches.length ? 'matched' : 'usage-only';
  }
  const usagesByKey = new Map<string, FeatureFlagUsage[]>();
  for (const usage of source.usages)
    if (usage.normalizedKey) {
      const existing = usagesByKey.get(usage.normalizedKey) ?? [];
      existing.push(usage);
      usagesByKey.set(usage.normalizedKey, existing);
    }
  const allKeys = new Set([...declarationsByKey.keys(), ...usagesByKey.keys()]);
  const flags: FeatureFlagContract[] = [...allKeys].sort().map((key) => {
    const flagDeclarations = declarationsByKey.get(key) ?? [];
    const flagUsages = usagesByKey.get(key) ?? [];
    const conflict = defaultConflict(flagDeclarations, flagUsages);
    return {
      id: `feature-flag-${stableId(key)}`,
      key: flagDeclarations[0]?.key ?? flagUsages[0]!.key!,
      normalizedKey: key,
      declarationIds: flagDeclarations.map((declaration) => declaration.id).sort(),
      usageIds: flagUsages.map((usage) => usage.id).sort(),
      status: conflict
        ? 'default-conflict'
        : !flagDeclarations.length
          ? 'usage-only'
          : !flagUsages.length
            ? 'declaration-only'
            : 'matched',
    };
  });
  if ((declarations.length || source.usages.length) && !providers.size)
    providers.add('Custom/local');
  const truncated =
    snapshot.truncated ||
    profile.truncated ||
    json.length + source.declarations.length > maximumDeclarations ||
    source.truncated;
  const status: FeatureFlagAnalysis['status'] =
    !declarations.length && !source.usages.length && !providers.size && !source.parseFailures
      ? 'unsupported'
      : truncated || source.parseFailures || profile.status !== 'complete'
        ? 'partial'
        : 'complete';
  const analysis: FeatureFlagAnalysis = {
    schemaVersion: 1,
    version: '1.0.0',
    status,
    providers: [...providers].sort(),
    declarations,
    usages: source.usages,
    flags,
    summary: {
      providers: providers.size,
      declarationFiles: new Set(declarations.map((declaration) => declaration.file)).size,
      declaredFlags: declarationsByKey.size,
      staticUsages: source.usages.filter((usage) => usage.key).length,
      dynamicUsages: source.usages.filter((usage) => !usage.key).length,
      matchedFlags: flags.filter((flag) => flag.status === 'matched').length,
      declarationOnly: flags.filter((flag) => flag.status === 'declaration-only').length,
      usageOnly: flags.filter((flag) => flag.status === 'usage-only').length,
      defaultConflicts: flags.filter((flag) => flag.status === 'default-conflict').length,
    },
    parseFailures: source.parseFailures,
    truncated,
    limitations: [
      'JSON and TypeScript are parsed as inert data or syntax; target modules, configuration, providers, and flag SDKs are never loaded or executed.',
      'Declarations are limited to JSON featureFlags maps and literal TypeScript definition collections with feature/flag-shaped names.',
      'Usages are limited to literal keys passed to recognized flag-evaluation calls; dynamic keys remain visible but unpaired.',
      'Different declaration defaults across files may represent plans, environments, or variants and are not treated as conflicts.',
      'A default conflict requires inconsistent literal source defaults, or one unambiguous declared default that differs from one literal source default.',
      'Declaration-only and usage-only records are consistency candidates, not proof that a feature is dead, unreachable, or incorrectly configured at runtime.',
    ],
  };
  return {
    analysis,
    run: {
      id: 'feature-flags',
      name: 'Feature flag declaration and usage consistency',
      status: status === 'unsupported' ? 'skipped' : status === 'partial' ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: 0,
      detail:
        status === 'unsupported'
          ? 'No supported feature flag declaration, provider, or evaluation call was captured.'
          : `Mapped ${analysis.summary.declaredFlags} declared flag(s), ${analysis.summary.staticUsages} literal usage(s), ${analysis.summary.dynamicUsages} dynamic usage(s), and ${analysis.summary.defaultConflicts} default conflict candidate(s).`,
      version: '1.0.0',
    },
  };
}
