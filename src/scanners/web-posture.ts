import ts from 'typescript';
import type { Finding, ScannerRun, Snapshot, SourceFile } from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import { isRuntimeSource } from '../security/paths.ts';

const nextRootPage = /^(?:src\/)?app\/page\.[cm]?[jt]sx?$|^pages\/index\.[cm]?[jt]sx?$/i;
const nextRootLayout = /^(?:src\/)?app\/layout\.[cm]?[jt]sx?$/i;
const robotsRoute = /^(?:src\/)?app\/robots\.[cm]?[jt]s$/i;
const sitemapRoute = /^(?:src\/)?app\/sitemap\.[cm]?[jt]s$/i;

function manifestFrameworks(snapshot: Snapshot): Set<string> {
  const manifest = snapshot.files.find(
    (file) => file.path === 'package.json' && isRuntimeSource(file),
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

function staticFile(snapshot: Snapshot, names: string[]): SourceFile | undefined {
  return snapshot.files.find(
    (file) => isRuntimeSource(file) && names.includes(file.path.toLowerCase()),
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
  const frameworks = manifestFrameworks(snapshot);
  const webFiles = snapshot.files.filter(
    (file) => isRuntimeSource(file) && /\.[cm]?[jt]sx?$/.test(file.path),
  );
  const entry = webFiles.find((file) => nextRootPage.test(file.path));
  const layout = webFiles.find((file) => nextRootLayout.test(file.path));
  const webProject = frameworks.has('next') || frameworks.has('react') || Boolean(entry || layout);
  if (!webProject)
    return {
      findings: [],
      run: {
        id: 'web-posture',
        name: 'Web discovery and SEO posture',
        status: 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: 'No React, Next.js, or conventional web entry point was identified.',
        version: '0.1.0',
      },
    };

  const findings: Finding[] = [];
  const evidenceFile = entry ?? layout ?? snapshot.files.find(isRuntimeSource)!;
  const robots = staticFile(snapshot, ['public/robots.txt', 'robots.txt']);
  const sitemap = staticFile(snapshot, ['public/sitemap.xml', 'sitemap.xml']);
  const llms = staticFile(snapshot, ['llms.txt', 'public/llms.txt']);
  const hasRobots = Boolean(robots || webFiles.some((file) => robotsRoute.test(file.path)));
  const hasSitemap = Boolean(sitemap || webFiles.some((file) => sitemapRoute.test(file.path)));

  if (entry && !hasRobots)
    findings.push(
      candidate(
        evidenceFile,
        'TW-WEB001',
        'Public web entry has no discoverable robots policy',
        'A public root page was detected, but no static robots.txt or Next.js robots metadata route was captured.',
        'Declare the intended crawler policy with public/robots.txt or app/robots.ts. Blocking crawlers is valid when intentional.',
        'Public root page exists without a captured robots policy.',
      ),
    );
  if (entry && !hasSitemap)
    findings.push(
      candidate(
        evidenceFile,
        'TW-WEB002',
        'Public web entry has no discoverable sitemap',
        'A public root page was detected, but no static sitemap.xml or Next.js sitemap metadata route was captured.',
        'Add a sitemap when search discovery matters, or record that the application is intentionally private.',
        'Public root page exists without a captured sitemap.',
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

  return {
    findings,
    run: {
      id: 'web-posture',
      name: 'Web discovery and SEO posture',
      status: snapshot.truncated ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: findings.length,
      detail: `Checked robots policy, sitemap, Next.js root metadata, and optional llms.txt presence. robots=${hasRobots ? 'present' : 'not found'}; sitemap=${hasSitemap ? 'present' : 'not found'}; llms.txt=${llms ? 'present' : 'not found'}. Deployment behavior was not inferred from source.`,
      version: '0.1.0',
    },
  };
}
