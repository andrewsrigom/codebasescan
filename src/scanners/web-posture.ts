import ts from 'typescript';
import type { Finding, ScannerRun, Snapshot, SourceFile } from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import { isRuntimeSource } from '../security/paths.ts';

const nextEntryPaths = [
  'app/page.tsx',
  'app/page.jsx',
  'app/page.ts',
  'app/page.js',
  'src/app/page.tsx',
  'src/app/page.jsx',
  'src/app/page.ts',
  'src/app/page.js',
  'pages/index.tsx',
  'pages/index.jsx',
  'pages/index.ts',
  'pages/index.js',
] as const;
const nextLayoutPaths = [
  'app/layout.tsx',
  'app/layout.jsx',
  'app/layout.ts',
  'app/layout.js',
  'src/app/layout.tsx',
  'src/app/layout.jsx',
  'src/app/layout.ts',
  'src/app/layout.js',
] as const;
const reactEntryPaths = [
  'src/main.tsx',
  'src/main.jsx',
  'src/main.ts',
  'src/main.js',
  'src/App.tsx',
  'src/App.jsx',
] as const;
const desktopFrameworkPackages = new Set([
  'electron',
  'electron-builder',
  '@tauri-apps/api',
  '@capacitor/core',
]);

function manifestFrameworks(snapshot: Snapshot, prefix = ''): Set<string> {
  const manifest = snapshot.files.find(
    (file) => file.path === componentPath(prefix, 'package.json') && isRuntimeSource(file),
  );
  if (!manifest) return new Set();
  try {
    const value = JSON.parse(manifest.content) as Record<string, unknown>;
    const dependencies = [value.dependencies, value.devDependencies].filter(
      (entry): entry is Record<string, unknown> =>
        Boolean(entry) && typeof entry === 'object' && !Array.isArray(entry),
    );
    return new Set(dependencies.flatMap((entry) => Object.keys(entry)));
  } catch {
    return new Set();
  }
}

function hasNextMetadata(file: SourceFile): boolean {
  const source = ts.createSourceFile(
    file.path,
    file.content,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const exported = (node: ts.Node) =>
    ts.canHaveModifiers(node) &&
    ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
  return source.statements.some((statement) => {
    if (
      ts.isFunctionDeclaration(statement) &&
      statement.name?.text === 'generateMetadata' &&
      exported(statement)
    )
      return true;
    return (
      ts.isVariableStatement(statement) &&
      exported(statement) &&
      statement.declarationList.declarations.some(
        (declaration) => ts.isIdentifier(declaration.name) && declaration.name.text === 'metadata',
      )
    );
  });
}

function candidate(
  file: SourceFile,
  ruleId: string,
  title: string,
  description: string,
  remediation: string,
  observation: string,
  severity: Finding['severity'] = 'info',
): Finding {
  const evidence = sourceEvidence(file, 1, observation);
  evidence.kind = 'inferred';
  return makeFinding({
    source: 'web',
    ruleId,
    title,
    category: 'configuration',
    severity,
    sourceSeverity: 'review',
    description,
    remediation,
    cwe: [],
    evidence: [evidence],
  });
}

function componentPath(prefix: string, relative: string): string {
  return prefix ? `${prefix}/${relative}` : relative;
}

function desktopContainer(snapshot: Snapshot, prefix: string, frameworks: Set<string>): boolean {
  if ([...desktopFrameworkPackages].some((dependency) => frameworks.has(dependency))) return true;
  const segments = prefix.split('/').filter(Boolean);
  const parent = segments.slice(0, -1).join('/');
  const nearbyRoots = new Set([prefix, parent]);
  const markers = [
    'wails.json',
    'tauri.conf.json',
    'src-tauri/tauri.conf.json',
    'electron-builder.yml',
    'electron-builder.yaml',
  ];
  return [...nearbyRoots].some((root) =>
    markers.some((marker) =>
      snapshot.files.some(
        (file) =>
          isRuntimeSource(file) &&
          file.path.toLowerCase() === componentPath(root, marker).toLowerCase(),
      ),
    ),
  );
}

function manifestRoots(snapshot: Snapshot): Set<string> {
  const roots = new Set<string>(['']);
  for (const file of snapshot.files) {
    if (!isRuntimeSource(file) || !file.path.endsWith('/package.json')) continue;
    roots.add(file.path.slice(0, -'/package.json'.length));
  }
  return roots;
}

function conventionalMonorepoRoots(files: SourceFile[]): Set<string> {
  const roots = new Set<string>();
  const entry =
    /^((?:apps|packages)\/[^/]+)\/(?:src\/)?(?:app\/(?:\([^/]+\)\/)?(?:page|layout)|pages\/index)\.[cm]?[jt]sx?$/i;
  for (const file of files) {
    const prefix = entry.exec(file.path)?.[1];
    if (prefix) roots.add(prefix);
  }
  return roots;
}

function componentFile(
  snapshot: Snapshot,
  prefix: string,
  relativePaths: string[],
): SourceFile | undefined {
  const expected = new Set(
    relativePaths.map((relative) => componentPath(prefix, relative).toLowerCase()),
  );
  return snapshot.files.find(
    (file) => isRuntimeSource(file) && expected.has(file.path.toLowerCase()),
  );
}

function groupedAppFile(
  snapshot: Snapshot,
  prefix: string,
  name: 'page' | 'layout',
): SourceFile | undefined {
  const base = prefix ? `${prefix}/` : '';
  const expected = new RegExp(`^(?:src/)?app/\\([^/]+\\)/${name}\\.[cm]?[jt]sx?$`, 'i');
  return snapshot.files.find((file) => {
    if (!isRuntimeSource(file) || !file.path.startsWith(base)) return false;
    return expected.test(file.path.slice(base.length));
  });
}

function componentEntry(snapshot: Snapshot, prefix: string): SourceFile | undefined {
  return (
    componentFile(snapshot, prefix, [...nextEntryPaths]) ??
    groupedAppFile(snapshot, prefix, 'page') ??
    componentFile(snapshot, prefix, [...reactEntryPaths])
  );
}

function componentLayout(snapshot: Snapshot, prefix: string): SourceFile | undefined {
  return (
    componentFile(snapshot, prefix, [...nextLayoutPaths]) ??
    groupedAppFile(snapshot, prefix, 'layout')
  );
}

function metadataRoute(snapshot: Snapshot, prefix: string, name: 'robots' | 'sitemap'): boolean {
  const basePaths = [
    componentPath(prefix, `app/${name}.`),
    componentPath(prefix, `src/app/${name}.`),
  ];
  return snapshot.files.some(
    (file) =>
      isRuntimeSource(file) &&
      basePaths.some(
        (base) =>
          file.path.toLowerCase().startsWith(base.toLowerCase()) &&
          /\.[cm]?[jt]s$/i.test(file.path),
      ),
  );
}

function blocksAllCrawlers(content: string): boolean {
  const lines = content
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*/, '').trim().toLowerCase())
    .filter(Boolean);
  let appliesToAll = false;
  for (const line of lines) {
    const [rawKey, ...rawValue] = line.split(':');
    const key = rawKey?.trim();
    const value = rawValue.join(':').trim();
    if (key === 'user-agent') appliesToAll = value === '*';
    if (appliesToAll && key === 'disallow' && value === '/') return true;
  }
  return false;
}

export function scanWebPosture(snapshot: Snapshot): { findings: Finding[]; run: ScannerRun } {
  const started = performance.now();
  const webFiles = snapshot.files.filter(
    (file) => isRuntimeSource(file) && /\.[cm]?[jt]sx?$/.test(file.path),
  );
  const candidatePrefixes = manifestRoots(snapshot);
  for (const prefix of conventionalMonorepoRoots(webFiles)) candidatePrefixes.add(prefix);
  const componentPrefixes = new Set<string>();
  let desktopEntriesExcluded = 0;
  for (const prefix of candidatePrefixes) {
    const frameworks = manifestFrameworks(snapshot, prefix);
    const nextEntry =
      componentFile(snapshot, prefix, [...nextEntryPaths]) ??
      groupedAppFile(snapshot, prefix, 'page');
    const nextLayout =
      componentFile(snapshot, prefix, [...nextLayoutPaths]) ??
      groupedAppFile(snapshot, prefix, 'layout');
    const reactEntry = componentFile(snapshot, prefix, [...reactEntryPaths]);
    if (nextEntry || nextLayout || (frameworks.has('react') && reactEntry)) {
      if (desktopContainer(snapshot, prefix, frameworks)) {
        desktopEntriesExcluded++;
        continue;
      }
      componentPrefixes.add(prefix);
    }
  }
  if (componentPrefixes.size === 0)
    return {
      findings: [],
      run: {
        id: 'web-posture',
        name: 'Web discovery and SEO posture',
        status: 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail:
          desktopEntriesExcluded > 0
            ? `No public-web application entry point was identified. ${desktopEntriesExcluded} desktop-container entry point(s) were excluded from Web Presence.`
            : 'No React, Next.js, or conventional web entry point was identified.',
        version: '0.5.0',
      },
    };

  const findings: Finding[] = [];
  let robotsPresent = 0;
  let sitemapsPresent = 0;
  let llmsPresent = 0;
  for (const prefix of componentPrefixes) {
    const entry = componentEntry(snapshot, prefix);
    const layout = componentLayout(snapshot, prefix);
    const evidenceFile = entry ?? layout;
    if (!evidenceFile) continue;
    const robots = componentFile(snapshot, prefix, ['public/robots.txt', 'robots.txt']);
    const sitemap = componentFile(snapshot, prefix, ['public/sitemap.xml', 'sitemap.xml']);
    const llms = componentFile(snapshot, prefix, ['llms.txt', 'public/llms.txt']);
    const hasRobots = Boolean(robots || metadataRoute(snapshot, prefix, 'robots'));
    const hasSitemap = Boolean(sitemap || metadataRoute(snapshot, prefix, 'sitemap'));
    robotsPresent += Number(hasRobots);
    sitemapsPresent += Number(hasSitemap);
    llmsPresent += Number(Boolean(llms));

    if (entry && !hasRobots)
      findings.push(
        candidate(
          evidenceFile,
          'TW-WEB001',
          'Web entry has no discoverable robots policy',
          'A web entry was detected, but no static robots.txt or Next.js robots metadata route was captured for this app.',
          'If this app is deployed on the public web, declare the intended crawler policy with public/robots.txt or app/robots.ts. Private applications can record this as intentional.',
          'Web entry exists without a captured robots policy in the same app.',
        ),
      );
    if (entry && !hasSitemap)
      findings.push(
        candidate(
          evidenceFile,
          'TW-WEB002',
          'Web entry has no discoverable sitemap',
          'A web entry was detected, but no static sitemap.xml or Next.js sitemap metadata route was captured for this app.',
          'Add a sitemap when public search discovery matters, or record that the application is intentionally private.',
          'Web entry exists without a captured sitemap in the same app.',
        ),
      );
    if (robots && blocksAllCrawlers(robots.content))
      findings.push(
        candidate(
          robots,
          'TW-WEB003',
          'Static robots policy blocks every crawler',
          'The captured static robots.txt applies Disallow: / to the wildcard user agent. This can be correct for private applications.',
          'Confirm this is intentional for the deployed environment and keep production and preview crawler policies separate.',
          'Wildcard crawler group contains a root-wide disallow directive.',
        ),
      );
    if (sitemap && !/<(?:urlset|sitemapindex)(?:\s|>)/i.test(sitemap.content))
      findings.push(
        candidate(
          sitemap,
          'TW-WEB004',
          'Static sitemap has no recognized root element',
          'The captured sitemap.xml does not contain a urlset or sitemapindex root element.',
          'Generate a valid sitemap document and verify its public URL after deployment.',
          'Static sitemap lacks a recognized sitemap root element.',
          'low',
        ),
      );
    if (layout && !hasNextMetadata(layout))
      findings.push(
        candidate(
          layout,
          'TW-WEB005',
          'Next.js root layout has no metadata export',
          'The root App Router layout has no static metadata export or generateMetadata function.',
          'Declare useful title and description metadata at the root or explicitly generate it.',
          'Root layout has no exported metadata declaration.',
        ),
      );
  }

  return {
    findings,
    run: {
      id: 'web-posture',
      name: 'Web discovery and SEO posture',
      status: snapshot.truncated ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: findings.length,
      detail: `Checked ${componentPrefixes.size} web app root(s) for robots policy, sitemap, Next.js metadata, and optional llms.txt presence. robots=${robotsPresent}; sitemap=${sitemapsPresent}; llms.txt=${llmsPresent}. Deployment behavior was not inferred from source.`,
      version: '0.5.0',
    },
  };
}
