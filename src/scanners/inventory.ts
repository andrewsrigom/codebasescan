import path from 'node:path';
import { parseDocument } from 'yaml';
import type { Dependency, Snapshot, SourceFile } from '../domain/types.ts';

type Scope = Dependency['scope'];
interface Declaration {
  requestedVersion: string;
  manifest: string;
  scope: Scope;
}

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function declarations(snapshot: Snapshot): Map<string, Declaration> {
  const result = new Map<string, Declaration>();
  for (const file of snapshot.files) {
    if (file.path.split('/').at(-1) !== 'package.json') continue;
    try {
      const manifest = object(JSON.parse(file.content));
      if (!manifest) continue;
      for (const [key, scope] of [
        ['dependencies', 'runtime'],
        ['devDependencies', 'development'],
      ] as const) {
        const section = object(manifest[key]);
        if (!section) continue;
        for (const [name, version] of Object.entries(section))
          if (typeof version === 'string' && !result.has(name))
            result.set(name, { requestedVersion: version, manifest: file.path, scope });
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
  declared: Map<string, Declaration>,
  name: string,
  version: string,
  development: boolean,
  needle: string,
  directOverride?: boolean,
): Dependency | null {
  if (!name || !version || name.length > 214 || version.length > 200) return null;
  const declaration = declared.get(name);
  const direct = directOverride ?? Boolean(declaration);
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
  };
}

function npmName(packagePath: string, entry: Record<string, unknown>): string {
  if (typeof entry.name === 'string') return entry.name;
  const marker = 'node_modules/';
  const index = packagePath.lastIndexOf(marker);
  return index < 0 ? '' : packagePath.slice(index + marker.length);
}

function npmLock(file: SourceFile, declared: Map<string, Declaration>): Dependency[] {
  const root = object(JSON.parse(file.content));
  if (!root) return [];
  const packages = object(root.packages);
  if (packages) {
    const output: Dependency[] = [];
    for (const [packagePath, raw] of Object.entries(packages)) {
      if (!packagePath) continue;
      const entry = object(raw);
      if (!entry || typeof entry.version !== 'string') continue;
      const name = npmName(packagePath, entry);
      const item = dependency(
        file,
        declared,
        name,
        entry.version,
        entry.dev === true,
        `"${packagePath}"`,
      );
      if (item) output.push(item);
    }
    return output;
  }
  const output: Dependency[] = [];
  const walk = (tree: Record<string, unknown>, direct: boolean) => {
    for (const [name, raw] of Object.entries(tree)) {
      const entry = object(raw);
      if (!entry || typeof entry.version !== 'string') continue;
      const item = dependency(
        file,
        declared,
        name,
        entry.version,
        entry.dev === true,
        `"${name}"`,
        direct,
      );
      if (item) output.push(item);
      const nested = object(entry.dependencies);
      if (nested) walk(nested, false);
    }
  };
  const tree = object(root.dependencies);
  if (tree) walk(tree, true);
  return output;
}

function pnpmPackageKey(key: string): { name: string; version: string } | null {
  const normalized = key.replace(/^\//, '');
  const legacy = /^(@[^/]+\/[^/]+|[^/]+)\/([^/]+)$/.exec(normalized);
  if (legacy?.[1] && legacy[2]) return { name: legacy[1], version: legacy[2].split('(')[0] ?? '' };
  const split = normalized.lastIndexOf('@');
  if (split <= 0) return null;
  return {
    name: normalized.slice(0, split),
    version: normalized.slice(split + 1).split('(')[0] ?? '',
  };
}

function pnpmLock(file: SourceFile, declared: Map<string, Declaration>): Dependency[] {
  const document = parseDocument(file.content, { schema: 'core' });
  if (document.errors.length) throw new Error('Invalid pnpm lockfile.');
  const root = object(document.toJS({ maxAliasCount: 20 }));
  const packages = object(root?.packages);
  if (!packages) return [];
  const output: Dependency[] = [];
  for (const [key, raw] of Object.entries(packages)) {
    const parsed = pnpmPackageKey(key);
    if (!parsed) continue;
    const entry = object(raw);
    const item = dependency(file, declared, parsed.name, parsed.version, entry?.dev === true, key);
    if (item) output.push(item);
  }
  return output;
}

function yarnClassic(file: SourceFile, declared: Map<string, Declaration>): Dependency[] {
  const output: Dependency[] = [];
  const stanza = /^(?:"([^"]+)"|([^\s][^:]*)):\s*\n\s+version\s+["']([^"']+)["']/gm;
  for (const match of file.content.matchAll(stanza)) {
    const selector = match[1] ?? match[2] ?? '';
    const first = selector.split(',')[0]?.trim().replace(/^"|"$/g, '') ?? '';
    const split = first.startsWith('@') ? first.indexOf('@', 1) : first.indexOf('@');
    const name = split > 0 ? first.slice(0, split) : '';
    const version = match[3] ?? '';
    const item = dependency(file, declared, name, version, false, match[0], declared.has(name));
    if (item) output.push(item);
  }
  return output;
}

function yarnBerry(file: SourceFile, declared: Map<string, Declaration>): Dependency[] {
  const document = parseDocument(file.content, { schema: 'core' });
  if (document.errors.length) throw new Error('Invalid Yarn lockfile.');
  const root = object(document.toJS({ maxAliasCount: 20 }));
  if (!root) return [];
  const output: Dependency[] = [];
  for (const [selector, raw] of Object.entries(root)) {
    if (selector === '__metadata') continue;
    const entry = object(raw);
    if (!entry || typeof entry.version !== 'string') continue;
    const first = selector.split(',')[0]?.trim() ?? '';
    const npmMarker = first.lastIndexOf('@npm:');
    const fallback = first.startsWith('@') ? first.indexOf('@', 1) : first.indexOf('@');
    const split = npmMarker > 0 ? npmMarker : fallback;
    const name = split > 0 ? first.slice(0, split) : '';
    const item = dependency(
      file,
      declared,
      name,
      entry.version,
      false,
      selector,
      declared.has(name),
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
  for (const file of snapshot.files) {
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
  for (const item of dependencies)
    records.set(`${item.lockfile}:${item.name}:${item.resolvedVersion}`, item);
  for (const [name, declaration] of declared) {
    if ([...records.values()].some((item) => item.name === name && item.relationship === 'direct'))
      continue;
    records.set(`manifest:${declaration.manifest}:${name}`, {
      name,
      requestedVersion: declaration.requestedVersion,
      manifest: declaration.manifest,
      scope: declaration.scope,
      relationship: 'direct',
    });
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
