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
  let total = 0;
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
  total =
    unusedFiles.size +
    unusedDependencies.size +
    unlistedDependencies.length +
    unusedExports.length +
    unusedTypes.length;
  return {
    schemaVersion: 1,
    unusedFiles: [...unusedFiles].sort().slice(0, maximumDeadCodeItems),
    unusedDependencies: [...unusedDependencies].sort().slice(0, maximumDeadCodeItems),
    unlistedDependencies: unlistedDependencies.slice(0, maximumDeadCodeItems),
    unusedExports: unusedExports.slice(0, maximumDeadCodeItems),
    unusedTypes: unusedTypes.slice(0, maximumDeadCodeItems),
    truncated: snapshot.truncated || total > maximumDeadCodeItems * 5,
  };
}

function rootManifest(snapshot: Snapshot): Record<string, unknown> {
  const file = snapshot.files.find((item) => item.path === 'package.json');
  if (!file) return { name: 'traceward-staged-project', private: true };
  try {
    const manifest = record(JSON.parse(file.content));
    const dependencySections = Object.fromEntries(
      ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].flatMap(
        (key) => {
          const section = record(manifest[key]);
          const safe = Object.fromEntries(
            Object.entries(section).filter(
              (entry): entry is [string, string] => typeof entry[1] === 'string',
            ),
          );
          return Object.keys(safe).length ? [[key, safe]] : [];
        },
      ),
    );
    return {
      name:
        typeof manifest.name === 'string'
          ? manifest.name.slice(0, 214)
          : 'traceward-staged-project',
      private: true,
      ...(manifest.type === 'module' ? { type: 'module' } : {}),
      ...dependencySections,
    };
  } catch {
    return { name: 'traceward-staged-project', private: true };
  }
}

function knipEntries(snapshot: Snapshot, profile?: ProjectProfile): string[] {
  const entries = new Set(profile?.entrypoints.map((entrypoint) => entrypoint.file) ?? []);
  for (const file of snapshot.files.filter(supportedSource))
    if (
      /(?:^|\/)(?:page|layout|route|middleware|proxy|instrumentation|index|main|server)\.[cm]?[jt]sx?$/.test(
        file.path,
      ) ||
      /(?:^|\/)pages\/.+\.[cm]?[jt]sx?$/.test(file.path)
    )
      entries.add(file.path);
  return [...entries].sort();
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
    await writeSnapshotStage(snapshot, sourceRoot, supportedSource);
    await writeFile(path.join(sourceRoot, 'package.json'), JSON.stringify(rootManifest(snapshot)), {
      mode: 0o600,
      flag: 'wx',
    });
    const pluginConfig = Object.fromEntries(disabledKnipPlugins.map((name) => [name, false]));
    await writeFile(
      path.join(sourceRoot, configName),
      JSON.stringify({
        entry: entries,
        project: ['**/*.{js,jsx,cjs,mjs,ts,tsx,cts,mts}'],
        include: ['files', 'dependencies', 'unlisted', 'exports', 'types'],
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
        '--strict',
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
    const analysis = normalizeKnip(JSON.parse(result.stdout) as unknown, snapshot);
    const compatibility = scannerCompatibility('knip', version);
    const partial = analysis.truncated || compatibility.status !== 'tested';
    return {
      analysis,
      run: {
        id: 'knip',
        name: 'Dead code and dependency usage',
        status: partial ? 'partial' : 'completed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: `${analysis.unusedFiles.length} unused file candidate(s), ${analysis.unusedDependencies.length} unused dependency candidate(s), and ${analysis.unusedExports.length + analysis.unusedTypes.length} unused export candidate(s). All target plugins and configuration loaders were disabled. ${compatibility.detail}`,
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
        detail: `${measured.functionsAnalyzed} function(s) measured; ${measured.hotspots.length} complexity, size, or parameter hotspot(s). ${artifacts.length} existing coverage artifact(s) imported. Metrics are review evidence, not vulnerabilities.`,
        version: '0.1.0',
      },
      deadCode.run,
    ],
  };
}
