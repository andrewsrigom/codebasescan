import path from 'node:path';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import ts from 'typescript';
import type {
  CodeQualityAnalysis,
  CoverageArtifactSummary,
  DeadCodeAnalysis,
  DeadCodeSymbol,
  FunctionHotspot,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';
import { record } from '../domain/validation.ts';
import { isRuntimeSource, safeRelative } from '../security/paths.ts';
import { runScannerProcess } from '../security/process.ts';
import { scannerCompatibility } from './external.ts';
import { writeSnapshotStage } from './staging.ts';
import { redact } from '../security/redact.ts';
import {
  declarativeKnipConfiguration,
  declarativeWorkspacePatterns,
  sanitizedManifest,
  typeScriptPathAliases,
  type TypeScriptPathAlias,
} from './declarative-config.ts';

const sourceExtension = /\.[cm]?[jt]sx?$/i;
const maximumHotspots = 200;
const maximumDeadCodeItems = 300;
const maximumNodesPerFile = 200_000;
const disabledKnipPlugins =
  'angular,astro,astro-db,astro-markdoc,astro-og-canvas,ava,babel,biome,borp,bumpp,bun,c8,capacitor,catalyst,changelogen,changelogithub,changesets,commitizen,commitlint,convex,create-typescript-app,cspell,cucumber,cypress,danger,dependency-cruiser,docusaurus,dotenv,drizzle,electron-vite,eleventy,esbuild,eslint,eve,execa,expo,expressive-code,fast,fumadocs,gatsby,github-action,github-actions,glob,graphql-codegen,hardhat,husky,i18next-parser,jest,karma,knex,ladle,laravel-vite-plugin,lefthook,lint-staged,linthtml,lit,lockfile-lint,lost-pixel,lunaria,markdownlint,marko,mdx,mdxlint,metro,mise,mocha,moonrepo,msw,nano-spawn,nano-staged,nest,netlify,next,next-intl,next-mdx,nitro,node,node-modules-inspector,nodemon,npm-package-json-lint,nuxt,nuxtjs-i18n,nx,nyc,oclif,openapi-ts,openclaw,orval,oxfmt,oxlint,panda-css,parcel,payload,pino,playwright,playwright-ct,playwright-test,plop,pm2,pnpm,postcss,pre-commit,preconstruct,prettier,prisma,quasar,qwik,raycast,react-cosmos,react-email,react-native,react-router,relay,release-it,remark,remix,rolldown,rollup,rsbuild,rslib,rspack,rstest,sanity,semantic-release,sentry,serverless-framework,simple-git-hooks,size-limit,sst,starlight,stencil,storybook,stryker,stylelint,svelte,sveltejs-package,sveltekit,svgo,svgr,swc,syncpack,tailwind,tanstack-router,taskfile,tauri,temporal,travis,ts-node,tsd,tsdown,tsup,tsx,typedoc,typescript,unbuild,unocss,unplugin-auto-import,unplugin-icons,unplugin-vue-components,unplugin-vue-i18n,unplugin-vue-markdown,unplugin-vue-router,vercel,vercel-og,vike,vite,vite-plugin-pages,vite-plugin-pwa,vite-plugin-vue-layouts-next,vite-plus,vite-pwa-assets-generator,vitepress,vitest,vue,webdriver-io,webpack,wireit,wrangler,wxt,xo,yarn,yorkie,zx'.split(
    ',',
  );

export interface QualityScanResult {
  analysis: CodeQualityAnalysis;
  runs: ScannerRun[];
}

function supportedSource(file: SourceFile): boolean {
  return (
    isRuntimeSource(file) && sourceExtension.test(file.path) && !/\.d\.[cm]?ts$/i.test(file.path)
  );
}

function knipSource(file: SourceFile): boolean {
  return sourceExtension.test(file.path) && !/\.d\.[cm]?ts$/i.test(file.path);
}

function scriptKind(file: string): ts.ScriptKind {
  if (file.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (file.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (/\.[cm]?js$/i.test(file)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function functionName(node: ts.FunctionLikeDeclaration, source: ts.SourceFile): string {
  if ('name' in node && node.name) {
    if (ts.isIdentifier(node.name) || ts.isStringLiteralLike(node.name)) return node.name.text;
    return node.name.getText(source).slice(0, 120);
  }
  if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    ts.isVariableDeclaration(node.parent) &&
    ts.isIdentifier(node.parent.name)
  )
    return node.parent.name.text;
  return `anonymous@${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`;
}

function functionComplexity(node: ts.FunctionLikeDeclaration): number {
  let complexity = 1;
  const visit = (child: ts.Node): void => {
    if (child !== node && ts.isFunctionLike(child)) return;
    if (
      ts.isIfStatement(child) ||
      ts.isConditionalExpression(child) ||
      ts.isForStatement(child) ||
      ts.isForInStatement(child) ||
      ts.isForOfStatement(child) ||
      ts.isWhileStatement(child) ||
      ts.isDoStatement(child) ||
      ts.isCaseClause(child) ||
      ts.isCatchClause(child)
    )
      complexity++;
    else if (
      ts.isBinaryExpression(child) &&
      [
        ts.SyntaxKind.AmpersandAmpersandToken,
        ts.SyntaxKind.BarBarToken,
        ts.SyntaxKind.QuestionQuestionToken,
      ].includes(child.operatorToken.kind)
    )
      complexity++;
    ts.forEachChild(child, visit);
  };
  if (node.body) visit(node.body);
  return complexity;
}

export function measureCodeQuality(snapshot: Snapshot): {
  filesAnalyzed: number;
  functionsAnalyzed: number;
  hotspotCount: number;
  hotspots: FunctionHotspot[];
  truncated: boolean;
} {
  const hotspots: FunctionHotspot[] = [];
  let functionsAnalyzed = 0;
  let truncated = snapshot.truncated;
  const files = snapshot.files.filter(supportedSource);
  for (const file of files) {
    const source = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    let nodes = 0;
    const visit = (node: ts.Node): void => {
      if (++nodes > maximumNodesPerFile) {
        truncated = true;
        return;
      }
      if (ts.isFunctionLike(node) && 'body' in node && node.body) {
        const declaration = node as ts.FunctionLikeDeclaration;
        functionsAnalyzed++;
        const start = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
        const end = source.getLineAndCharacterOfPosition(node.end).line + 1;
        const complexity = functionComplexity(declaration);
        const parameters = declaration.parameters.length;
        const lines = Math.max(1, end - start + 1);
        if (complexity >= 15 || lines >= 80 || parameters >= 6)
          hotspots.push({
            file: file.path,
            line: start,
            name: functionName(declaration, source),
            lines,
            parameters,
            complexity,
          });
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  hotspots.sort(
    (left, right) =>
      right.complexity - left.complexity ||
      right.lines - left.lines ||
      left.file.localeCompare(right.file) ||
      left.line - right.line,
  );
  return {
    filesAnalyzed: files.length,
    functionsAnalyzed,
    hotspotCount: hotspots.length,
    hotspots: hotspots.slice(0, maximumHotspots),
    truncated: truncated || hotspots.length > maximumHotspots,
  };
}

function percentage(value: unknown): number | undefined {
  const item = record(value);
  return typeof item.pct === 'number' && Number.isFinite(item.pct)
    ? Math.min(100, Math.max(0, Number(item.pct.toFixed(2))))
    : undefined;
}

export function coverageArtifacts(snapshot: Snapshot): CoverageArtifactSummary[] {
  const summaries: CoverageArtifactSummary[] = [];
  for (const file of snapshot.files) {
    if (/(?:^|\/)coverage-summary\.json$/.test(file.path)) {
      try {
        const total = record(record(JSON.parse(file.content)).total);
        if (!Object.keys(total).length) continue;
        summaries.push({
          file: file.path,
          ...(percentage(total.lines) !== undefined ? { lines: percentage(total.lines) } : {}),
          ...(percentage(total.statements) !== undefined
            ? { statements: percentage(total.statements) }
            : {}),
          ...(percentage(total.functions) !== undefined
            ? { functions: percentage(total.functions) }
            : {}),
          ...(percentage(total.branches) !== undefined
            ? { branches: percentage(total.branches) }
            : {}),
        });
      } catch {
        // Malformed coverage artifacts are omitted; the quality run explains the bounded import.
      }
    } else if (/(?:^|\/)lcov\.info$/.test(file.path)) {
      const values = new Map<string, number>();
      for (const key of ['LF', 'LH', 'FNF', 'FNH', 'BRF', 'BRH']) {
        const total = [...file.content.matchAll(new RegExp(`^${key}:(\\d+)$`, 'gm'))].reduce(
          (sum, match) => sum + Number(match[1] ?? 0),
          0,
        );
        values.set(key, total);
      }
      const ratio = (covered: string, found: string) => {
        const denominator = values.get(found) ?? 0;
        return denominator
          ? Number((((values.get(covered) ?? 0) / denominator) * 100).toFixed(2))
          : undefined;
      };
      summaries.push({
        file: file.path,
        ...(ratio('LH', 'LF') !== undefined ? { lines: ratio('LH', 'LF') } : {}),
        ...(ratio('FNH', 'FNF') !== undefined ? { functions: ratio('FNH', 'FNF') } : {}),
        ...(ratio('BRH', 'BRF') !== undefined ? { branches: ratio('BRH', 'BRF') } : {}),
      });
    }
  }
  return summaries.slice(0, 10);
}

function safeSnapshotPath(snapshot: Snapshot, value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const candidate = safeRelative(value.replace(/^\.\//, ''));
    return snapshot.files.some((file) => file.path === candidate) ? candidate : undefined;
  } catch {
    return undefined;
  }
}

function symbols(
  row: Record<string, unknown>,
  key: 'unlisted' | 'exports' | 'types',
  file: string,
): DeadCodeSymbol[] {
  if (!Array.isArray(row[key])) return [];
  return row[key].flatMap((raw) => {
    const item = record(raw);
    if (typeof item.name !== 'string') return [];
    const line =
      typeof item.line === 'number' && Number.isSafeInteger(item.line) && item.line > 0
        ? item.line
        : 1;
    return [{ file, line, name: item.name.slice(0, 500) }];
  });
}

export function normalizeKnip(value: unknown, snapshot: Snapshot): DeadCodeAnalysis {
  const envelope = record(value);
  if (!Array.isArray(envelope.issues)) throw new Error('Unsupported Knip JSON schema.');
  const unusedFiles = new Set<string>();
  const unusedDependencies = new Set<string>();
  const unlistedDependencies: DeadCodeSymbol[] = [];
  const unusedExports: DeadCodeSymbol[] = [];
  const unusedTypes: DeadCodeSymbol[] = [];
  for (const raw of envelope.issues) {
    const row = record(raw);
    const file = safeSnapshotPath(snapshot, row.file);
    if (!file) continue;
    if (Array.isArray(row.files) && row.files.length) unusedFiles.add(file);
    for (const key of ['dependencies', 'devDependencies'] as const)
      if (Array.isArray(row[key]))
        for (const rawDependency of row[key]) {
          const dependency = record(rawDependency);
          if (typeof dependency.name === 'string')
            unusedDependencies.add(dependency.name.slice(0, 214));
        }
    unlistedDependencies.push(...symbols(row, 'unlisted', file));
    unusedExports.push(...symbols(row, 'exports', file));
    unusedTypes.push(...symbols(row, 'types', file));
  }
  return {
    schemaVersion: 1,
    unusedFileCount: unusedFiles.size,
    unusedFiles: [...unusedFiles].sort().slice(0, maximumDeadCodeItems),
    unusedDependencyCount: unusedDependencies.size,
    unusedDependencies: [...unusedDependencies].sort().slice(0, maximumDeadCodeItems),
    unlistedDependencyCount: unlistedDependencies.length,
    unlistedDependencies: unlistedDependencies.slice(0, maximumDeadCodeItems),
    unusedExportCount: unusedExports.length,
    unusedExports: unusedExports.slice(0, maximumDeadCodeItems),
    unusedTypeCount: unusedTypes.length,
    unusedTypes: unusedTypes.slice(0, maximumDeadCodeItems),
    truncated:
      snapshot.truncated ||
      unusedFiles.size > maximumDeadCodeItems ||
      unusedDependencies.size > maximumDeadCodeItems ||
      unlistedDependencies.length > maximumDeadCodeItems ||
      unusedExports.length > maximumDeadCodeItems ||
      unusedTypes.length > maximumDeadCodeItems,
  };
}

function knipEntries(snapshot: Snapshot, profile?: ProjectProfile): string[] {
  const entries = new Set(profile?.entrypoints.map((entrypoint) => entrypoint.file) ?? []);
  const manifestEntries = declarativeManifestHints(snapshot).entries;
  for (const entry of manifestEntries) entries.add(entry);
  for (const file of snapshot.files.filter(knipSource)) {
    if (!isRuntimeSource(file)) entries.add(file.path);
    if (
      /(?:^|\/)(?:page|layout|route|middleware|proxy|instrumentation|index|main|server)\.[cm]?[jt]sx?$/.test(
        file.path,
      ) ||
      /(?:^|\/)(?:[^/]+\.)?config\.[cm]?[jt]s$/.test(file.path) ||
      /(?:^|\/)instrumentation-client\.[cm]?[jt]s$/.test(file.path) ||
      /(?:^|\/)pages\/.+\.[cm]?[jt]sx?$/.test(file.path)
    )
      entries.add(file.path);
  }
  return [...entries].sort();
}

function nestedStrings(value: unknown, output: string[], depth = 0): void {
  if (output.length >= 500 || depth > 5) return;
  if (typeof value === 'string') {
    output.push(value.slice(0, 2000));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) nestedStrings(item, output, depth + 1);
    return;
  }
  if (value && typeof value === 'object')
    for (const item of Object.values(value)) nestedStrings(item, output, depth + 1);
}

function declarativeManifestHints(snapshot: Snapshot): { entries: string[]; commands: string[] } {
  const entries = new Set<string>();
  const commands: string[] = [];
  const sourcePaths = new Set(snapshot.files.filter(knipSource).map((file) => file.path));
  for (const file of snapshot.files) {
    if (!isRuntimeSource(file) || file.path.split('/').at(-1) !== 'package.json') continue;
    try {
      const manifest = record(JSON.parse(file.content));
      const directory = path.posix.dirname(file.path) === '.' ? '' : path.posix.dirname(file.path);
      const scripts = record(manifest.scripts);
      const manifestCommands: string[] = [];
      for (const command of Object.values(scripts).slice(0, 500))
        if (typeof command === 'string') manifestCommands.push(command.slice(0, 2000));
      commands.push(...manifestCommands);
      const references: string[] = [...manifestCommands];
      for (const key of ['main', 'module', 'browser', 'bin', 'exports'])
        nestedStrings(manifest[key], references);
      for (const reference of references) {
        for (const candidate of sourcePaths) {
          if (directory && !candidate.startsWith(`${directory}/`)) continue;
          const relative = directory ? candidate.slice(directory.length + 1) : candidate;
          if (reference.includes(relative) || reference.includes(`./${relative}`))
            entries.add(candidate);
        }
      }
    } catch {
      // The inventory scanner reports malformed manifests separately.
    }
  }
  return { entries: [...entries].sort(), commands: commands.slice(0, 1000) };
}

function packageDirectories(snapshot: Snapshot): string[] {
  return snapshot.files
    .filter((file) => isRuntimeSource(file) && file.path.split('/').at(-1) === 'package.json')
    .map((file) => path.posix.dirname(file.path))
    .filter((directory) => directory !== '.')
    .sort((left, right) => right.length - left.length || left.localeCompare(right));
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : [];
}

function configuredPathAliases(
  snapshot: Snapshot,
  aliases: TypeScriptPathAlias[],
): Map<string, Record<string, string[]>> {
  const directories = packageDirectories(snapshot);
  const result = new Map<string, Record<string, string[]>>();
  for (const alias of [...aliases].sort(
    (left, right) => left.configFile.length - right.configFile.length,
  )) {
    const configDirectory = path.posix.dirname(alias.configFile);
    const workspace =
      directories.find(
        (directory) => configDirectory === directory || configDirectory.startsWith(`${directory}/`),
      ) ?? '.';
    const workspaceDirectory = workspace === '.' ? '' : workspace;
    const paths = result.get(workspace) ?? {};
    paths[alias.pattern] = alias.targets.map((target) => {
      const relative = path.posix.relative(workspaceDirectory, target);
      return relative.startsWith('.') ? relative : `./${relative}`;
    });
    result.set(workspace, paths);
  }
  return result;
}

function generatedKnipConfig(
  snapshot: Snapshot,
  profile: ProjectProfile | undefined,
  imported: Record<string, unknown>,
  aliases: TypeScriptPathAlias[],
): Record<string, unknown> {
  const entries = knipEntries(snapshot, profile);
  const directories = packageDirectories(snapshot);
  const rootEntries = entries.filter(
    (entry) => !directories.some((directory) => entry.startsWith(`${directory}/`)),
  );
  const configuredWorkspaces =
    imported.workspaces &&
    typeof imported.workspaces === 'object' &&
    !Array.isArray(imported.workspaces)
      ? (imported.workspaces as Record<string, unknown>)
      : {};
  const workspaces: Record<string, unknown> = { ...configuredWorkspaces };
  const pathAliases = configuredPathAliases(snapshot, aliases);
  for (const directory of directories) {
    const configured =
      workspaces[directory] &&
      typeof workspaces[directory] === 'object' &&
      !Array.isArray(workspaces[directory])
        ? (workspaces[directory] as Record<string, unknown>)
        : {};
    const generatedEntries = entries
      .filter((entry) => entry.startsWith(`${directory}/`))
      .map((entry) => entry.slice(directory.length + 1));
    workspaces[directory] = {
      ...configured,
      ...(pathAliases.has(directory)
        ? {
            paths: {
              ...(configured.paths as Record<string, unknown> | undefined),
              ...pathAliases.get(directory),
            },
          }
        : {}),
      entry: [...new Set([...stringArray(configured.entry), ...generatedEntries])],
      project: stringArray(configured.project).length
        ? stringArray(configured.project)
        : ['**/*.{js,jsx,cjs,mjs,ts,tsx,cts,mts}'],
    };
  }
  if (Object.keys(workspaces).length) {
    const rootConfigured =
      workspaces['.'] && typeof workspaces['.'] === 'object' && !Array.isArray(workspaces['.'])
        ? (workspaces['.'] as Record<string, unknown>)
        : {};
    const rootSettings = Object.fromEntries(
      Object.entries(imported).filter(([key]) => key !== 'workspaces'),
    );
    workspaces['.'] = {
      ...rootSettings,
      ...rootConfigured,
      ...(pathAliases.has('.')
        ? {
            paths: {
              ...(rootSettings.paths as Record<string, unknown> | undefined),
              ...(rootConfigured.paths as Record<string, unknown> | undefined),
              ...pathAliases.get('.'),
            },
          }
        : {}),
      entry: [
        ...new Set([
          ...stringArray(rootSettings.entry),
          ...stringArray(rootConfigured.entry),
          ...rootEntries,
        ]),
      ],
      project: stringArray(rootConfigured.project).length
        ? stringArray(rootConfigured.project)
        : stringArray(rootSettings.project).length
          ? stringArray(rootSettings.project)
          : ['**/*.{js,jsx,cjs,mjs,ts,tsx,cts,mts}'],
    };
    return { workspaces };
  }
  return {
    ...imported,
    ...(pathAliases.has('.')
      ? {
          paths: {
            ...(imported.paths as Record<string, unknown> | undefined),
            ...pathAliases.get('.'),
          },
        }
      : {}),
    entry: [...new Set([...stringArray(imported.entry), ...rootEntries])],
    project: stringArray(imported.project).length
      ? stringArray(imported.project)
      : ['**/*.{js,jsx,cjs,mjs,ts,tsx,cts,mts}'],
    ...(Object.keys(workspaces).length ? { workspaces } : {}),
  };
}

async function writeSanitizedManifests(snapshot: Snapshot, sourceRoot: string): Promise<void> {
  const workspacePatterns = declarativeWorkspacePatterns(snapshot).filter(
    (pattern) => pattern !== '.',
  );
  const manifests = snapshot.files.filter(
    (file) => isRuntimeSource(file) && file.path.split('/').at(-1) === 'package.json',
  );
  if (!manifests.some((file) => file.path === 'package.json'))
    manifests.unshift({
      path: 'package.json',
      content: '{}',
      bytes: 2,
      digest: '',
      scope: 'runtime',
    });
  for (const file of manifests) {
    const target = path.join(sourceRoot, safeRelative(file.path));
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, JSON.stringify(sanitizedManifest(file, workspacePatterns)), {
      mode: 0o600,
      flag: 'wx',
    });
  }
}

function externalPackageName(specifier: string): string | undefined {
  if (/^(?:\.|\/|#|node:|bun:|file:)/.test(specifier)) return undefined;
  if (specifier.startsWith('@')) {
    const [scope, name] = specifier.split('/');
    return scope && name ? `${scope}/${name}` : undefined;
  }
  return specifier.split('/')[0] || undefined;
}

function sourceReferencedPackages(
  snapshot: Snapshot,
  profile: ProjectProfile | undefined,
  dependencyNames: Set<string>,
): Set<string> {
  const packages = new Set<string>();
  const add = (specifier: string) => {
    const name = externalPackageName(specifier);
    if (name) packages.add(name);
  };
  for (const item of profile?.imports ?? []) add(item.specifier);
  for (const file of snapshot.files.filter(supportedSource)) {
    const isConfiguration = /(?:^|\/)(?:[^/]+\.)?config\.[cm]?[jt]s$/.test(file.path);
    const source = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    const visit = (node: ts.Node): void => {
      if (ts.isStringLiteralLike(node)) {
        for (const name of dependencyNames)
          if (
            node.text.includes(`node_modules/${name}/`) ||
            (isConfiguration && (node.text === name || node.text.startsWith(`${name}/`)))
          )
            packages.add(name);
      }
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier &&
        ts.isStringLiteralLike(node.moduleSpecifier)
      )
        add(node.moduleSpecifier.text);
      else if (ts.isCallExpression(node) && node.arguments.length) {
        const argument = node.arguments[0];
        const dynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
        const commonJs = ts.isIdentifier(node.expression) && node.expression.text === 'require';
        const requireResolve =
          ts.isPropertyAccessExpression(node.expression) &&
          ts.isIdentifier(node.expression.expression) &&
          node.expression.expression.text === 'require' &&
          node.expression.name.text === 'resolve';
        if (
          (dynamicImport || commonJs || requireResolve) &&
          argument &&
          ts.isStringLiteralLike(argument)
        )
          add(argument.text);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  for (const command of declarativeManifestHints(snapshot).commands)
    for (const name of dependencyNames) {
      const escaped = name.replace(/[|\\{}()[\]^$+*?.-]/g, '\\$&');
      if (new RegExp(`(?:^|[\\s;&|])${escaped}(?=$|[\\s;&|])`).test(command)) packages.add(name);
    }
  return packages;
}

function dependencyPatternMatches(name: string, pattern: string): boolean {
  const escaped = pattern.replace(/[|\\{}()[\]^$+?.]/g, '\\$&').replaceAll('*', '.*');
  return new RegExp(`^${escaped}$`).test(name);
}

function ignoredDependencyPatterns(config: Record<string, unknown>): string[] {
  const ignored = new Set(stringArray(config.ignoreDependencies));
  const workspaces =
    config.workspaces && typeof config.workspaces === 'object' && !Array.isArray(config.workspaces)
      ? (config.workspaces as Record<string, unknown>)
      : {};
  for (const workspace of Object.values(workspaces))
    if (workspace && typeof workspace === 'object' && !Array.isArray(workspace))
      for (const pattern of stringArray((workspace as Record<string, unknown>).ignoreDependencies))
        ignored.add(pattern);
  return [...ignored];
}

function unusedRuntimeDependencies(
  snapshot: Snapshot,
  profile: ProjectProfile | undefined,
  ignoredPatterns: string[],
): string[] {
  const dependencyNames = new Set<string>();
  for (const file of snapshot.files) {
    if (!isRuntimeSource(file) || file.path.split('/').at(-1) !== 'package.json') continue;
    try {
      for (const name of Object.keys(record(record(JSON.parse(file.content)).dependencies)))
        dependencyNames.add(name);
    } catch {
      // The inventory scanner reports malformed manifests separately.
    }
  }
  const referenced = sourceReferencedPackages(snapshot, profile, dependencyNames);
  const implicit = new Set<string>();
  if (profile?.frameworks.some((framework) => framework.id.startsWith('nextjs-')))
    for (const name of ['next', 'react', 'react-dom', 'sharp']) implicit.add(name);
  else if (snapshot.files.some((file) => supportedSource(file) && /\.[jt]sx$/i.test(file.path)))
    for (const name of ['react', 'react-dom']) implicit.add(name);
  const unused = new Set<string>();
  for (const file of snapshot.files) {
    if (!isRuntimeSource(file) || file.path.split('/').at(-1) !== 'package.json') continue;
    try {
      const dependencies = record(record(JSON.parse(file.content)).dependencies);
      for (const name of Object.keys(dependencies))
        if (
          !name.startsWith('@types/') &&
          !referenced.has(name) &&
          !implicit.has(name) &&
          !ignoredPatterns.some((pattern) => dependencyPatternMatches(name, pattern))
        )
          unused.add(name);
    } catch {
      // The inventory scanner reports malformed manifests separately.
    }
  }
  return [...unused].sort();
}

async function knipVersion(cwd: string, signal?: AbortSignal): Promise<string | undefined> {
  try {
    const result = await runScannerProcess('knip', ['--version'], cwd, signal);
    return result.code === 0 ? /\d+\.\d+\.\d+/.exec(result.stdout)?.[0] : undefined;
  } catch {
    return undefined;
  }
}

async function scanDeadCode(
  snapshot: Snapshot,
  profile: ProjectProfile | undefined,
  temporaryDirectory: string,
  signal?: AbortSignal,
): Promise<{ analysis?: DeadCodeAnalysis; run: ScannerRun }> {
  const started = performance.now();
  const entries = knipEntries(snapshot, profile);
  if (!entries.length)
    return {
      run: {
        id: 'knip',
        name: 'Dead code and dependency usage',
        status: 'skipped',
        durationMs: 0,
        findings: 0,
        detail:
          'No trusted application entry point was identified, so dead-code reachability was not inferred.',
      },
    };
  await mkdir(temporaryDirectory, { recursive: true, mode: 0o700 });
  const stage = await mkdtemp(path.join(temporaryDirectory, 'knip-'));
  const sourceRoot = path.join(stage, 'source');
  const configName = 'traceward.knip.json';
  try {
    await writeSnapshotStage(snapshot, sourceRoot, knipSource);
    await writeSanitizedManifests(snapshot, sourceRoot);
    const importedConfig = declarativeKnipConfiguration(snapshot);
    const aliasConfiguration = typeScriptPathAliases(snapshot);
    const trustedConfig = generatedKnipConfig(
      snapshot,
      profile,
      importedConfig.config,
      aliasConfiguration.aliases,
    );
    const pluginConfig = Object.fromEntries(disabledKnipPlugins.map((name) => [name, false]));
    await writeFile(
      path.join(sourceRoot, configName),
      JSON.stringify({
        ...trustedConfig,
        include: ['files', 'unlisted', 'exports', 'types'],
        ...pluginConfig,
      }),
      { mode: 0o600, flag: 'wx' },
    );
    const version = await knipVersion(sourceRoot, signal);
    const result = await runScannerProcess(
      'knip',
      [
        '--config',
        configName,
        '--reporter',
        'json',
        '--no-progress',
        '--no-gitignore',
        '--no-config-hints',
        '--no-tag-hints',
        '--no-exit-code',
      ],
      sourceRoot,
      signal,
    );
    if (result.code !== 0)
      throw new Error(
        `Knip returned an error: ${redact(result.stderr).replaceAll(sourceRoot, '[stage]').slice(0, 500)}`,
      );
    const normalized = normalizeKnip(JSON.parse(result.stdout) as unknown, snapshot);
    const dependencyCandidates = new Set(
      unusedRuntimeDependencies(
        snapshot,
        profile,
        ignoredDependencyPatterns(importedConfig.config),
      ),
    );
    const analysis: DeadCodeAnalysis = {
      ...normalized,
      unusedDependencyCount: dependencyCandidates.size,
      unusedDependencies: [...dependencyCandidates].sort().slice(0, maximumDeadCodeItems),
      truncated: normalized.truncated || dependencyCandidates.size > maximumDeadCodeItems,
    };
    const compatibility = scannerCompatibility('knip', version);
    const configurationIssues = [...importedConfig.issues, ...aliasConfiguration.issues];
    const partial =
      analysis.truncated || compatibility.status !== 'tested' || configurationIssues.length > 0;
    const configurationDetail = importedConfig.sources.length
      ? ` Applied declarative settings from ${importedConfig.sources.join(', ')}.`
      : '';
    const configurationIssueDetail = configurationIssues.length
      ? ` ${configurationIssues.join(' ')}`
      : '';
    const unusedFileCount = analysis.unusedFileCount ?? analysis.unusedFiles.length;
    const unusedDependencyCount =
      analysis.unusedDependencyCount ?? analysis.unusedDependencies.length;
    const unusedSymbolCount =
      (analysis.unusedExportCount ?? analysis.unusedExports.length) +
      (analysis.unusedTypeCount ?? analysis.unusedTypes.length);
    return {
      analysis,
      run: {
        id: 'knip',
        name: 'Dead code and dependency usage',
        status: partial ? 'partial' : 'completed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: `${unusedFileCount} unused file candidate(s) found (${analysis.unusedFiles.length} retained), ${unusedDependencyCount} source-unreferenced runtime dependency candidate(s) found (${analysis.unusedDependencies.length} retained), and ${unusedSymbolCount} unused export/type candidate(s) found (${analysis.unusedExports.length + analysis.unusedTypes.length} retained). All target plugins and executable configuration loaders were disabled.${configurationDetail}${configurationIssueDetail} ${compatibility.detail}`,
        ...(version ? { version } : {}),
      },
    };
  } catch (error) {
    return {
      run: {
        id: 'knip',
        name: 'Dead code and dependency usage',
        status: 'failed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: `Dead-code analysis did not complete (${error instanceof Error ? error.message.slice(0, 500) : 'unknown error'}). No clean result is implied.`,
      },
    };
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

export async function scanCodeQuality(
  snapshot: Snapshot,
  profile: ProjectProfile | undefined,
  temporaryDirectory: string,
  signal?: AbortSignal,
): Promise<QualityScanResult> {
  const started = performance.now();
  const measured = measureCodeQuality(snapshot);
  const artifacts = coverageArtifacts(snapshot);
  const deadCode = await scanDeadCode(snapshot, profile, temporaryDirectory, signal);
  return {
    analysis: {
      schemaVersion: 1,
      filesAnalyzed: measured.filesAnalyzed,
      functionsAnalyzed: measured.functionsAnalyzed,
      hotspotCount: measured.hotspotCount,
      hotspots: measured.hotspots,
      ...(deadCode.analysis ? { deadCode: deadCode.analysis } : {}),
      coverageArtifacts: artifacts,
      truncated: measured.truncated || Boolean(deadCode.analysis?.truncated),
    },
    runs: [
      {
        id: 'quality-metrics',
        name: 'TypeScript and JavaScript quality metrics',
        status: measured.truncated ? 'partial' : measured.filesAnalyzed ? 'completed' : 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: `${measured.functionsAnalyzed} function(s) measured; ${measured.hotspotCount} complexity, size, or parameter hotspot(s) found (${measured.hotspots.length} retained). ${artifacts.length} existing coverage artifact(s) imported. Metrics are review evidence, not vulnerabilities.`,
        version: '0.2.0',
      },
      deadCode.run,
    ],
  };
}
