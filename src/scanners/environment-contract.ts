import ts from 'typescript';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import type {
  EnvironmentContractAnalysis,
  EnvironmentContractLocation,
  Finding,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';
import { isRuntimeSource } from '../security/paths.ts';

const sourcePattern = /\.[cm]?[jt]sx?$/i;
const templatePattern = /(?:^|\/)\.env(?:\.[A-Za-z0-9_-]+)*\.(?:example|sample|template)$/i;
const maximumVariables = 5_000;
const maximumNamedAccesses = 20_000;
const maximumDeclarations = 5_000;
const maximumLocationsPerVariable = 20;
const maximumDynamicAccesses = 100;
const maximumFindings = 300;
const platformVariables = new Set([
  'CI',
  'COREPACK_ENABLE_DOWNLOAD_PROMPT',
  'GIT_COMMIT_SHA',
  'HOST',
  'HOSTNAME',
  'NODE_OPTIONS',
  'NODE_ENV',
  'PORT',
  'USER',
  'NEXT_RUNTIME',
  'VERCEL',
  'VERCEL_ENV',
  'VERCEL_REGION',
  'VERCEL_TARGET_ENV',
  'VERCEL_URL',
  'VERCEL_GIT_PROVIDER',
  'VERCEL_GIT_REPO_SLUG',
  'VERCEL_GIT_REPO_OWNER',
  'VERCEL_GIT_REPO_ID',
  'VERCEL_GIT_COMMIT_REF',
  'VERCEL_GIT_COMMIT_SHA',
  'VERCEL_GIT_COMMIT_MESSAGE',
  'VERCEL_GIT_COMMIT_AUTHOR_LOGIN',
  'VERCEL_GIT_COMMIT_AUTHOR_NAME',
]);
const viteVariables = new Set(['MODE', 'BASE_URL', 'PROD', 'DEV', 'SSR']);
const reviewCandidateName =
  /(?:AUTH|CREDENTIAL|DATABASE|ENCRYPT|PASSWORD|POSTGRES|PRIVATE|REDIS|SECRET|STRIPE|TOKEN|WEBHOOK)/i;

interface NamedAccess extends EnvironmentContractLocation {
  name: string;
  source: ts.SourceFile;
  fileSource: SourceFile;
  node: ts.Node;
}

function scriptKind(file: string): ts.ScriptKind {
  if (/\.[cm]?tsx$/i.test(file)) return ts.ScriptKind.TSX;
  if (/\.jsx$/i.test(file)) return ts.ScriptKind.JSX;
  if (/\.[cm]?js$/i.test(file)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function isClientModule(source: ts.SourceFile): boolean {
  return source.statements.some(
    (statement) =>
      ts.isExpressionStatement(statement) &&
      ts.isStringLiteral(statement.expression) &&
      statement.expression.text === 'use client',
  );
}

function environmentBase(
  expression: ts.Expression,
  source: ts.SourceFile,
): EnvironmentContractLocation['syntax'] | null {
  const text = expression.getText(source).replaceAll(' ', '');
  if (text === 'process.env') return 'process.env';
  if (text === 'import.meta.env') return 'import.meta.env';
  return null;
}

function accessContext(
  syntax: EnvironmentContractLocation['syntax'],
  name: string,
  clientModule: boolean,
): EnvironmentContractLocation['context'] {
  return clientModule || syntax === 'import.meta.env' || name.startsWith('NEXT_PUBLIC_')
    ? 'client'
    : 'server';
}

function collectSourceAccesses(
  file: SourceFile,
  namedLimit: number,
  dynamicLimit: number,
): {
  accesses: NamedAccess[];
  dynamic: EnvironmentContractAnalysis['dynamicAccesses'];
  parseFailed: boolean;
  truncated: boolean;
} {
  const source = ts.createSourceFile(
    file.path,
    file.content,
    ts.ScriptTarget.Latest,
    true,
    scriptKind(file.path),
  );
  const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
    .parseDiagnostics;
  if (diagnostics?.length)
    return { accesses: [], dynamic: [], parseFailed: true, truncated: false };
  const clientModule = isClientModule(source);
  const accesses: NamedAccess[] = [];
  const dynamic: EnvironmentContractAnalysis['dynamicAccesses'] = [];
  let truncated = false;
  const add = (
    name: string,
    syntax: EnvironmentContractLocation['syntax'],
    node: ts.Node,
  ): void => {
    if (accesses.length >= namedLimit) {
      truncated = true;
      return;
    }
    accesses.push({
      name,
      syntax,
      context: accessContext(syntax, name, clientModule),
      file: file.path,
      line: lineOf(source, node),
      source,
      fileSource: file,
      node,
    });
  };
  const visit = (node: ts.Node): void => {
    if (ts.isPropertyAccessExpression(node)) {
      const syntax = environmentBase(node.expression, source);
      if (syntax) add(node.name.text, syntax, node);
    } else if (ts.isElementAccessExpression(node)) {
      const syntax = environmentBase(node.expression, source);
      if (syntax) {
        const argument = node.argumentExpression;
        if (argument && ts.isStringLiteralLike(argument)) add(argument.text, syntax, node);
        else if (dynamic.length < dynamicLimit)
          dynamic.push({ file: file.path, line: lineOf(source, node), syntax });
        else truncated = true;
      }
    } else if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer
    ) {
      const syntax = environmentBase(node.initializer, source);
      if (syntax)
        for (const element of node.name.elements) {
          const property = element.propertyName ?? element.name;
          if (ts.isIdentifier(property) || ts.isStringLiteralLike(property))
            add(property.text, syntax, element);
        }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { accesses, dynamic, parseFailed: false, truncated };
}

function declaredVariables(file: SourceFile): { names: string[]; truncated: boolean } {
  const names = new Set<string>();
  let truncated = false;
  for (const line of file.content.split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (!match?.[1] || names.has(match[1])) continue;
    if (names.size >= maximumDeclarations) {
      truncated = true;
      continue;
    }
    names.add(match[1]);
  }
  return { names: [...names], truncated };
}

function providedByPlatform(name: string, syntaxes: Set<EnvironmentContractLocation['syntax']>) {
  return (
    platformVariables.has(name) || (syntaxes.has('import.meta.env') && viteVariables.has(name))
  );
}

function contractFinding(access: NamedAccess): Finding {
  const evidence = sourceEvidence(
    access.fileSource,
    access.line,
    `Environment name ${access.name} is referenced but absent from captured environment templates. No value was read.`,
  );
  evidence.kind = 'inferred';
  return makeFinding({
    source: 'environment',
    ruleId: 'TW-ENV001',
    title: 'Environment variable is missing from captured templates',
    category: 'configuration',
    severity: 'low',
    sourceSeverity: 'review',
    description:
      'A named environment variable is referenced in captured runtime source but is not declared in any captured sanitized .env example, sample, or template. A deployment platform may still provide it.',
    remediation:
      'Declare the variable name without a real value in the appropriate environment template, or document the platform-owned contract. Never copy production secrets into example files.',
    cwe: [],
    evidence: [evidence],
  });
}

export function scanEnvironmentContract(snapshot: Snapshot): {
  analysis: EnvironmentContractAnalysis;
  findings: Finding[];
  run: ScannerRun;
} {
  const started = performance.now();
  const templates = snapshot.files.filter((file) => templatePattern.test(file.path));
  const declarationFiles = new Map<string, string[]>();
  const templateSummaries: EnvironmentContractAnalysis['templates'] = [];
  let declarationTruncated = false;
  for (const template of templates) {
    const declarations = declaredVariables(template);
    declarationTruncated ||= declarations.truncated;
    templateSummaries.push({ file: template.path, variables: declarations.names.length });
    for (const name of declarations.names) {
      if (!declarationFiles.has(name) && declarationFiles.size >= maximumDeclarations) {
        declarationTruncated = true;
        continue;
      }
      declarationFiles.set(name, [...(declarationFiles.get(name) ?? []), template.path]);
    }
  }

  const sourceFiles = snapshot.files.filter(
    (file) => isRuntimeSource(file) && sourcePattern.test(file.path),
  );
  const named: NamedAccess[] = [];
  const dynamicAccesses: EnvironmentContractAnalysis['dynamicAccesses'] = [];
  let parseFailures = 0;
  let sourceAccessesTruncated = false;
  for (const file of sourceFiles) {
    const namedLimit = maximumNamedAccesses - named.length;
    const dynamicLimit = maximumDynamicAccesses - dynamicAccesses.length;
    if (namedLimit <= 0) {
      sourceAccessesTruncated = true;
      break;
    }
    const result = collectSourceAccesses(file, namedLimit, dynamicLimit);
    parseFailures += Number(result.parseFailed);
    sourceAccessesTruncated ||= result.truncated;
    named.push(...result.accesses);
    dynamicAccesses.push(
      ...result.dynamic.slice(0, maximumDynamicAccesses - dynamicAccesses.length),
    );
  }

  const byName = new Map<string, NamedAccess[]>();
  for (const access of named) byName.set(access.name, [...(byName.get(access.name) ?? []), access]);
  const variableNames = [...byName.keys()].sort().slice(0, maximumVariables);
  const variables = variableNames.map((name): EnvironmentContractAnalysis['variables'][number] => {
    const accesses = byName.get(name) ?? [];
    const declaredIn = [...new Set(declarationFiles.get(name) ?? [])].sort();
    const syntaxes = new Set(accesses.map((access) => access.syntax));
    const status = providedByPlatform(name, syntaxes)
      ? 'platform-provided'
      : declaredIn.length
        ? 'documented'
        : templates.length
          ? 'undocumented'
          : 'unverified';
    return {
      name,
      status,
      declaredIn,
      locations: accesses.slice(0, maximumLocationsPerVariable).map((access) => ({
        file: access.file,
        line: access.line,
        syntax: access.syntax,
        context: access.context,
      })),
      truncated: accesses.length > maximumLocationsPerVariable,
    };
  });
  const undocumented = variables
    .filter((variable) => variable.status === 'undocumented')
    .map((variable) => variable.name);
  const unverified = variables
    .filter((variable) => variable.status === 'unverified')
    .map((variable) => variable.name);
  const usedNames = new Set(byName.keys());
  const unusedDeclarations = [...declarationFiles.keys()]
    .filter((name) => !usedNames.has(name))
    .sort();
  const truncated =
    snapshot.truncated ||
    parseFailures > 0 ||
    declarationTruncated ||
    sourceAccessesTruncated ||
    byName.size > maximumVariables ||
    dynamicAccesses.length >= maximumDynamicAccesses ||
    variables.some((variable) => variable.truncated);
  const status: EnvironmentContractAnalysis['status'] =
    sourceFiles.length || templates.length ? (truncated ? 'partial' : 'complete') : 'unsupported';
  const analysis: EnvironmentContractAnalysis = {
    schemaVersion: 1,
    version: '1.0.0',
    status,
    templates: templateSummaries,
    variables,
    undocumented,
    unverified,
    unusedDeclarations,
    dynamicAccesses,
    summary: {
      used: variables.length,
      documented: variables.filter((variable) => variable.status === 'documented').length,
      undocumented: undocumented.length,
      platformProvided: variables.filter((variable) => variable.status === 'platform-provided')
        .length,
      unverified: unverified.length,
      unusedDeclarations: unusedDeclarations.length,
      dynamicAccesses: dynamicAccesses.length,
    },
    truncated,
    limitations: [
      'Only named process.env, import.meta.env, and direct destructuring accesses in captured JavaScript or TypeScript are compared.',
      'Template values are discarded before the snapshot; this analysis retains names only.',
      ...(templates.length
        ? [
            'A name missing from captured templates may still be intentionally supplied by deployment infrastructure.',
          ]
        : [
            'No captured environment template was available, so non-platform names remain unverified rather than undocumented.',
          ]),
      'Unused declarations may be consumed by frameworks, package scripts, external services, or files outside the bounded snapshot.',
      'Only security-, authentication-, credential-, data-service-, or payment-shaped undocumented names become findings; all other mismatches remain visible in this contract.',
    ],
  };
  const findingNames = undocumented.filter((name) => reviewCandidateName.test(name));
  const findings = findingNames.slice(0, maximumFindings).flatMap((name) => {
    const first = byName.get(name)?.[0];
    return first ? [contractFinding(first)] : [];
  });
  return {
    analysis,
    findings,
    run: {
      id: 'environment-contract',
      name: 'Environment contract consistency',
      status: status === 'unsupported' ? 'skipped' : status === 'partial' ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: findings.length,
      detail:
        status === 'unsupported'
          ? 'No supported runtime source or sanitized environment template was available.'
          : `Compared ${variables.length} named environment use(s) with ${templates.length} sanitized template(s); ${undocumented.length} undocumented (${findingNames.length} high-signal review candidates), ${unverified.length} unverified, ${unusedDeclarations.length} declared but not observed, and ${dynamicAccesses.length} dynamic access(es). Values were not retained.`,
      version: '1.0.0',
    },
  };
}
