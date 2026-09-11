import path from 'node:path';
import { parseDocument } from 'yaml';
import type { Dependency, Snapshot, SourceFile } from '../domain/types.ts';
import { isRuntimeSource } from '../security/paths.ts';

export const dependencyInventoryVersion = '0.2.0';

type Scope = Dependency['scope'];
interface Declaration {
  requestedVersion: string;
  manifest: string;
  scope: Scope;
}
type DeclarationMap = Map<string, Declaration[]>;

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function declarations(snapshot: Snapshot): DeclarationMap {
  const result: DeclarationMap = new Map();
  for (const file of snapshot.files.filter(isRuntimeSource)) {
    if (file.path.split('/').at(-1) !== 'package.json') continue;
    try {
      const manifest = object(JSON.parse(file.content));
      if (!manifest) continue;
      for (const [key, scope] of [
        ['dependencies', 'runtime'],
        ['optionalDependencies', 'runtime'],
        ['devDependencies', 'development'],
      ] as const) {
        const section = object(manifest[key]);
        if (!section) continue;
        for (const [name, version] of Object.entries(section)) {
          if (typeof version !== 'string') continue;
          const existing = result.get(name) ?? [];
          if (existing.some((item) => item.manifest === file.path && item.scope === scope))
            continue;
          result.set(name, [
            ...existing,
            { requestedVersion: version, manifest: file.path, scope },
          ]);
        }
      }
    } catch {
      /* Invalid manifests remain an explicit coverage limitation at scanner level. */
    }
  }
  return result;
}

function lockLine(file: SourceFile, needle: string): number {
  const index = file.content.indexOf(needle);
  return index < 0 ? 1 : file.content.slice(0, index).split('\n').length;
}

function dependency(
  file: SourceFile,
  declared: DeclarationMap,
  name: string,
  version: string,
  development: boolean,
  needle: string,
  directOverride?: boolean,
  parentChains?: string[][],
): Dependency | null {
  if (!name || !version || name.length > 214 || version.length > 200) return null;
  const declarations = declared.get(name) ?? [];
  const parentManifest = parentChains?.find((chain) => chain.length >= 2)?.[0];
  const declaredDependency =
    declarations.find((item) => item.manifest === parentManifest) ?? declarations[0];
  const direct = directOverride ?? declarations.length > 0;
  const declaration = direct ? declaredDependency : undefined;
  return {
    name,
    requestedVersion: declaration?.requestedVersion ?? version,
    resolvedVersion: version,
    manifest:
      declaration?.manifest ?? path.posix.join(path.posix.dirname(file.path), 'package.json'),
    scope: declaration?.scope ?? (development ? 'development' : 'runtime'),
    relationship: direct ? 'direct' : 'transitive',
    lockfile: file.path,
    lockfileLine: lockLine(file, needle),
    ...(parentChains?.length ? { parentChains } : {}),
  };
}

function npmName(packagePath: string, entry: Record<string, unknown>): string {
  if (typeof entry.name === 'string') return entry.name;
  const marker = 'node_modules/';
  const index = packagePath.lastIndexOf(marker);
  return index < 0 ? '' : packagePath.slice(index + marker.length);
}

const maximumParentChains = 3;
const maximumParentDepth = 12;

interface DependencyGraphSeed {
  node: string;
  chain: string[];
}

function dependencySections(
  entry: Record<string, unknown>,
  includeDevelopment = false,
): [string, unknown][] {
  const names = includeDevelopment
    ? ['dependencies', 'devDependencies', 'optionalDependencies']
    : ['dependencies', 'optionalDependencies'];
  return names.flatMap((name) => Object.entries(object(entry[name]) ?? {}));
}

function graphParentChains(
  labels: Map<string, string>,
  adjacency: Map<string, Set<string>>,
  seeds: DependencyGraphSeed[],
): Map<string, string[][]> {
  const chains = new Map<string, string[][]>();
  const queue: DependencyGraphSeed[] = [];
  const seenRoutes = new Set<string>();

  const enqueue = (node: string, chain: string[]) => {
    const label = labels.get(node);
    if (!label) return;
    const existing = chains.get(label) ?? [];
    const duplicate = existing.some(
      (candidate) => candidate.join('\u0000') === chain.join('\u0000'),
    );
    if (!duplicate && existing.length >= maximumParentChains) return;
    addParentChain(chains, label, chain);
    const routeKey = `${node}\u0000${chain.join('\u0000')}`;
    if (seenRoutes.has(routeKey)) return;
    seenRoutes.add(routeKey);
    queue.push({ node, chain });
  };

  for (const seed of seeds) enqueue(seed.node, seed.chain);
  let cursor = 0;
  while (cursor < queue.length && cursor < 20_000) {
    const current = queue[cursor++];
    if (!current || current.chain.length >= maximumParentDepth + 1) continue;
    for (const target of adjacency.get(current.node) ?? []) {
      const label = labels.get(target);
      if (!label || current.chain.includes(label)) continue;
      enqueue(target, [...current.chain, label]);
    }
  }
  return chains;
}

function resolveNpmPackagePath(
  packages: Record<string, unknown>,
  sourcePath: string,
  name: string,
): string | null {
  let directory = sourcePath;
  while (true) {
    const candidate = directory
      ? path.posix.join(directory, 'node_modules', name)
      : path.posix.join('node_modules', name);
    const entry = object(packages[candidate]);
    if (entry && entry.link !== true && typeof entry.version === 'string') return candidate;
    if (!directory) return null;
    const parent = path.posix.dirname(directory);
    directory = parent === '.' || parent === directory ? '' : parent;
  }
}

function npmParentChains(packages: Record<string, unknown>): Map<string, string[][]> {
  const labels = new Map<string, string>();
  const adjacency = new Map<string, Set<string>>();
  const seeds: DependencyGraphSeed[] = [];

  for (const [packagePath, raw] of Object.entries(packages)) {
    if (!packagePath || !packagePath.includes('node_modules/')) continue;
    const entry = object(raw);
    if (!entry || entry.link === true || typeof entry.version !== 'string') continue;
    const name = npmName(packagePath, entry);
    if (name) labels.set(packagePath, `${name}@${entry.version}`);
  }

  for (const [packagePath, raw] of Object.entries(packages)) {
    const entry = object(raw);
    if (!entry || entry.link === true) continue;
    if (labels.has(packagePath)) {
      const targets = new Set<string>();
      for (const [name] of dependencySections(entry)) {
        const target = resolveNpmPackagePath(packages, packagePath, name);
        if (target) targets.add(target);
      }
      adjacency.set(packagePath, targets);
      continue;
    }
    if (packagePath.includes('node_modules/')) continue;
    const manifest = packagePath ? path.posix.join(packagePath, 'package.json') : 'package.json';
    for (const [name] of dependencySections(entry, true)) {
      const target = resolveNpmPackagePath(packages, packagePath, name);
      const label = target ? labels.get(target) : undefined;
      if (target && label) seeds.push({ node: target, chain: [manifest, label] });
    }
  }
  return graphParentChains(labels, adjacency, seeds);
}

function npmLock(file: SourceFile, declared: DeclarationMap): Dependency[] {
  const root = object(JSON.parse(file.content));
  if (!root) return [];
  const packages = object(root.packages);
  if (packages) {
    const parentChains = npmParentChains(packages);
    const output: Dependency[] = [];
    for (const [packagePath, raw] of Object.entries(packages)) {
      if (!packagePath || !packagePath.includes('node_modules/')) continue;
      const entry = object(raw);
      if (!entry || entry.link === true || typeof entry.version !== 'string') continue;
      const name = npmName(packagePath, entry);
      const chains = parentChains.get(`${name}@${entry.version}`);
      const item = dependency(
        file,
        declared,
        name,
        entry.version,
        entry.dev === true,
        `"${packagePath}"`,
        chains ? chains.some((chain) => chain.length === 2) : undefined,
        chains,
      );
      if (item) output.push(item);
    }
    return output;
  }
  const output: Dependency[] = [];
  const walk = (tree: Record<string, unknown>, direct: boolean, parentChain: string[]) => {
    for (const [name, raw] of Object.entries(tree)) {
      const entry = object(raw);
      if (!entry || typeof entry.version !== 'string') continue;
      const chain = [...parentChain, `${name}@${entry.version}`];
      const item = dependency(
        file,
        declared,
        name,
        entry.version,
        entry.dev === true,
        `"${name}"`,
        direct,
        [chain],
      );
      if (item) output.push(item);
      const nested = object(entry.dependencies);
      if (nested) walk(nested, false, chain);
    }
  };
  const tree = object(root.dependencies);
  if (tree) walk(tree, true, ['package.json']);
  return output;
}

function pnpmPackageKey(key: string): { name: string; version: string } | null {
  const normalized = key.replace(/^\//, '');
  const packageVersion = normalized.split('(')[0] ?? normalized;
  const split = packageVersion.lastIndexOf('@');
  if (split > 0)
    return {
      name: packageVersion.slice(0, split),
      version: packageVersion.slice(split + 1),
    };
  const legacy = /^(@[^/]+\/[^/]+|[^/]+)\/([^/]+)$/.exec(packageVersion);
  return legacy?.[1] && legacy[2]
    ? { name: legacy[1], version: legacy[2].split('(')[0] ?? '' }
    : null;
}

function pnpmReference(name: string, raw: unknown): { name: string; version: string } | null {
  const entry = object(raw);
  const reference =
    typeof raw === 'string' ? raw : typeof entry?.version === 'string' ? entry.version : '';
  const normalized = reference.split('(')[0] ?? '';
  if (!normalized || /^(?:link|workspace|file):/.test(normalized)) return null;
  if (normalized.startsWith('npm:')) return pnpmPackageKey(normalized.slice(4));
  return { name, version: normalized };
}

function pnpmId(name: string, version: string): string {
  return `${name}@${version}`;
}

function addParentChain(chains: Map<string, string[][]>, id: string, chain: string[]): boolean {
  const existing = chains.get(id) ?? [];
  const key = chain.join('\u0000');
  if (existing.some((candidate) => candidate.join('\u0000') === key)) return false;
  if (existing.length >= maximumParentChains) return false;
  chains.set(id, [...existing, chain]);
  return true;
}

function pnpmParentChains(root: Record<string, unknown>): Map<string, string[][]> {
  const adjacency = new Map<string, Set<string>>();
  const graph = object(root.snapshots) ?? object(root.packages);
  for (const [key, raw] of Object.entries(graph ?? {})) {
    const source = pnpmPackageKey(key);
    const entry = object(raw);
    if (!source || !entry) continue;
    const sourceId = pnpmId(source.name, source.version);
    const targets = adjacency.get(sourceId) ?? new Set<string>();
    for (const sectionName of ['dependencies', 'optionalDependencies'] as const) {
      for (const [name, reference] of Object.entries(object(entry[sectionName]) ?? {})) {
        const target = pnpmReference(name, reference);
        if (target) targets.add(pnpmId(target.name, target.version));
      }
    }
    adjacency.set(sourceId, targets);
  }

  const chains = new Map<string, string[][]>();
  const queue: { id: string; chain: string[] }[] = [];
  for (const [importer, raw] of Object.entries(object(root.importers) ?? {})) {
    const entry = object(raw);
    if (!entry) continue;
    const manifest = importer === '.' ? 'package.json' : path.posix.join(importer, 'package.json');
    for (const sectionName of [
      'dependencies',
      'devDependencies',
      'optionalDependencies',
    ] as const) {
      for (const [name, reference] of Object.entries(object(entry[sectionName]) ?? {})) {
        const target = pnpmReference(name, reference);
        if (!target) continue;
        const id = pnpmId(target.name, target.version);
        const chain = [manifest, id];
        if (addParentChain(chains, id, chain)) queue.push({ id, chain });
      }
    }
  }

  let cursor = 0;
  while (cursor < queue.length && cursor < 20_000) {
    const current = queue[cursor++];
    if (!current || current.chain.length >= maximumParentDepth + 1) continue;
    for (const target of adjacency.get(current.id) ?? []) {
      if (current.chain.includes(target)) continue;
      const chain = [...current.chain, target];
      if (addParentChain(chains, target, chain)) queue.push({ id: target, chain });
    }
  }
  return chains;
}

function pnpmLock(file: SourceFile, declared: DeclarationMap): Dependency[] {
  const document = parseDocument(file.content, { schema: 'core' });
  if (document.errors.length) throw new Error('Invalid pnpm lockfile.');
  const root = object(document.toJS({ maxAliasCount: 20 }));
  const packages = object(root?.packages);
  if (!root || !packages) return [];
  const parentChains = pnpmParentChains(root);
  const output: Dependency[] = [];
  for (const [key, raw] of Object.entries(packages)) {
    const parsed = pnpmPackageKey(key);
    if (!parsed) continue;
    const entry = object(raw);
    const chains = parentChains.get(pnpmId(parsed.name, parsed.version));
    const item = dependency(
      file,
      declared,
      parsed.name,
      parsed.version,
      entry?.dev === true,
      key,
      chains ? chains.some((chain) => chain.length === 2) : undefined,
      chains,
    );
    if (item) output.push(item);
  }
  return output;
}

interface YarnGraphNode {
  key: string;
  name: string;
  version: string;
  selectors: string[];
  dependencies: [string, string][];
  needle: string;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  return /^(?:"[\s\S]*"|'[\s\S]*')$/.test(trimmed) ? trimmed.slice(1, -1) : trimmed;
}

function yarnSelectors(header: string): string[] {
  return (header.match(/"[^"]*"|'[^']*'|[^,]+/g) ?? []).map(unquote).filter(Boolean);
}

function yarnSelectorName(selector: string): string {
  const npmMarker = selector.lastIndexOf('@npm:');
  const split =
    npmMarker > 0
      ? npmMarker
      : selector.startsWith('@')
        ? selector.indexOf('@', 1)
        : selector.indexOf('@');
  return split > 0 ? selector.slice(0, split) : '';
}

function yarnGraphParentChains(
  nodes: YarnGraphNode[],
  declared: DeclarationMap,
  berry: boolean,
): Map<string, string[][]> {
  const labels = new Map(nodes.map((node) => [node.key, `${node.name}@${node.version}`]));
  const selectorToNode = new Map<string, string>();
  for (const node of nodes)
    for (const selector of node.selectors) selectorToNode.set(selector, node.key);

  const resolve = (name: string, reference: string) => {
    const candidates = [`${name}@${reference}`];
    if (berry && !reference.startsWith('npm:')) candidates.unshift(`${name}@npm:${reference}`);
    return candidates.map((candidate) => selectorToNode.get(candidate)).find(Boolean);
  };

  const adjacency = new Map<string, Set<string>>();
  for (const node of nodes) {
    const targets = new Set<string>();
    for (const [name, reference] of node.dependencies) {
      const target = resolve(name, reference);
      if (target) targets.add(target);
    }
    adjacency.set(node.key, targets);
  }

  const seeds: DependencyGraphSeed[] = [];
  for (const [name, declarations] of declared) {
    for (const declaration of declarations) {
      const target = resolve(name, declaration.requestedVersion);
      const label = target ? labels.get(target) : undefined;
      if (target && label) seeds.push({ node: target, chain: [declaration.manifest, label] });
    }
  }
  return graphParentChains(labels, adjacency, seeds);
}

function yarnClassicNodes(file: SourceFile): YarnGraphNode[] {
  const lines = file.content.split('\n');
  const nodes: YarnGraphNode[] = [];
  let cursor = 0;
  while (cursor < lines.length) {
    const headerLine = lines[cursor] ?? '';
    if (!headerLine || /^\s|^#/.test(headerLine) || !headerLine.endsWith(':')) {
      cursor++;
      continue;
    }
    const body: string[] = [];
    let next = cursor + 1;
    while (next < lines.length && (/^\s/.test(lines[next] ?? '') || !(lines[next] ?? ''))) {
      body.push(lines[next] ?? '');
      next++;
    }
    const selectors = yarnSelectors(headerLine.slice(0, -1));
    const name = yarnSelectorName(selectors[0] ?? '');
    const versionMatch = body
      .map((line) => /^\s{2}version\s+(["'][^"']+["']|\S+)\s*$/.exec(line))
      .find(Boolean);
    const version = unquote(versionMatch?.[1] ?? '');
    const dependencies: [string, string][] = [];
    let dependencySection = false;
    for (const line of body) {
      if (/^\s{2}(?:dependencies|optionalDependencies):\s*$/.test(line)) {
        dependencySection = true;
        continue;
      }
      if (/^\s{2}\S/.test(line)) dependencySection = false;
      if (!dependencySection || !/^\s{4}\S/.test(line)) continue;
      const match = /^\s{4}(["'][^"']+["']|\S+)\s+(["'][^"']+["']|\S+)\s*$/.exec(line);
      if (match?.[1] && match[2]) dependencies.push([unquote(match[1]), unquote(match[2])]);
    }
    if (name && version)
      nodes.push({
        key: `classic:${cursor}`,
        name,
        version,
        selectors,
        dependencies,
        needle: headerLine,
      });
    cursor = next;
  }
  return nodes;
}

function yarnClassic(file: SourceFile, declared: DeclarationMap): Dependency[] {
  const nodes = yarnClassicNodes(file);
  const parentChains = yarnGraphParentChains(nodes, declared, false);
  const output: Dependency[] = [];
  for (const node of nodes) {
    const chains = parentChains.get(`${node.name}@${node.version}`);
    const item = dependency(
      file,
      declared,
      node.name,
      node.version,
      false,
      node.needle,
      chains ? chains.some((chain) => chain.length === 2) : declared.has(node.name),
      chains,
    );
    if (item) output.push(item);
  }
  return output;
}

function yarnBerryNodes(root: Record<string, unknown>): YarnGraphNode[] {
  const nodes: YarnGraphNode[] = [];
  for (const [selector, raw] of Object.entries(root)) {
    if (selector === '__metadata') continue;
    const entry = object(raw);
    if (
      !entry ||
      typeof entry.version !== 'string' ||
      selector.includes('@workspace:') ||
      (typeof entry.resolution === 'string' && entry.resolution.includes('@workspace:'))
    )
      continue;
    const selectors = yarnSelectors(selector);
    const name = yarnSelectorName(selectors[0] ?? '');
    if (!name) continue;
    const dependencies = dependencySections(entry).flatMap(([dependencyName, reference]) =>
      typeof reference === 'string' ? ([[dependencyName, reference]] as [string, string][]) : [],
    );
    nodes.push({
      key: `berry:${selector}`,
      name,
      version: entry.version,
      selectors,
      dependencies,
      needle: selector,
    });
  }
  return nodes;
}

function yarnBerry(file: SourceFile, declared: DeclarationMap): Dependency[] {
  const document = parseDocument(file.content, { schema: 'core' });
  if (document.errors.length) throw new Error('Invalid Yarn lockfile.');
  const root = object(document.toJS({ maxAliasCount: 20 }));
  if (!root) return [];
  const nodes = yarnBerryNodes(root);
  const parentChains = yarnGraphParentChains(nodes, declared, true);
  const output: Dependency[] = [];
  for (const node of nodes) {
    const chains = parentChains.get(`${node.name}@${node.version}`);
    const item = dependency(
      file,
      declared,
      node.name,
      node.version,
      false,
      node.needle,
      chains ? chains.some((chain) => chain.length === 2) : declared.has(node.name),
      chains,
    );
    if (item) output.push(item);
  }
  return output;
}

export interface DependencyInventory {
  dependencies: Dependency[];
  lockfiles: string[];
  errors: string[];
}

export function resolvedInventory(snapshot: Snapshot): DependencyInventory {
  const declared = declarations(snapshot);
  const dependencies: Dependency[] = [];
  const lockfiles: string[] = [];
  const errors: string[] = [];
  for (const file of snapshot.files.filter(isRuntimeSource)) {
    const name = file.path.split('/').at(-1);
    if (
      !['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'].includes(
        name ?? '',
      )
    )
      continue;
    lockfiles.push(file.path);
    try {
      if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json')
        dependencies.push(...npmLock(file, declared));
      else if (name === 'pnpm-lock.yaml') dependencies.push(...pnpmLock(file, declared));
      else if (name === 'yarn.lock')
        dependencies.push(
          ...(file.content.trimStart().startsWith('__metadata:')
            ? yarnBerry(file, declared)
            : yarnClassic(file, declared)),
        );
    } catch {
      errors.push(file.path);
    }
  }
  const records = new Map<string, Dependency>();
  for (const item of dependencies) {
    const key = `${item.lockfile}:${item.name}:${item.resolvedVersion}`;
    const previous = records.get(key);
    if (!previous) records.set(key, item);
    else {
      const parentChains = [...(previous.parentChains ?? []), ...(item.parentChains ?? [])]
        .filter(
          (chain, index, values) =>
            values.findIndex((candidate) => candidate.join('\u0000') === chain.join('\u0000')) ===
            index,
        )
        .slice(0, maximumParentChains);
      records.set(key, { ...previous, ...(parentChains.length ? { parentChains } : {}) });
    }
  }
  for (const [name, declarations] of declared) {
    for (const declaration of declarations) {
      const represented = [...records.values()].some(
        (item) =>
          item.name === name &&
          item.relationship === 'direct' &&
          (item.manifest === declaration.manifest ||
            item.parentChains?.some((chain) => chain[0] === declaration.manifest)),
      );
      if (represented) continue;
      records.set(`manifest:${declaration.manifest}:${name}`, {
        name,
        requestedVersion: declaration.requestedVersion,
        manifest: declaration.manifest,
        scope: declaration.scope,
        relationship: 'direct',
      });
    }
  }
  return {
    dependencies: [...records.values()].sort(
      (a, b) =>
        a.name.localeCompare(b.name) ||
        (a.resolvedVersion ?? '').localeCompare(b.resolvedVersion ?? ''),
    ),
    lockfiles,
    errors,
  };
}

export function inventory(snapshot: Snapshot): Dependency[] {
  return resolvedInventory(snapshot).dependencies;
}
