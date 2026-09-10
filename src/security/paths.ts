import path from 'node:path';
import os from 'node:os';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath, readdir } from 'node:fs/promises';
import ignore from 'ignore';
import { digest } from '../domain/findings.ts';
import type { ProjectScopeEstimate, Snapshot, SourceFile, SourceScope } from '../domain/types.ts';
import { redact } from './redact.ts';
const ignoredDirectories = new Set([
  '.git',
  'node_modules',
  '.next',
  '.next-dev',
  '.pnpm-store',
  'dist',
  'build',
  'out',
  'output',
  'coverage',
  'storybook-static',
  'test-results',
  'traceward-report',
  '.traceward',
  '.turbo',
  '.venv',
  'vendor',
]);
const extensions = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.json',
  '.jsonc',
  '.yaml',
  '.yml',
  '.toml',
  '.sql',
]);
const excludedFiles = new Set([
  '.gitleaks.toml',
  '.semgrepignore',
  '.semgrep.yml',
  '.semgrep.yaml',
]);
const testSegments = new Set([
  'test',
  'tests',
  '__tests__',
  'fixture',
  'fixtures',
  'e2e',
  'cypress',
  'playwright',
  'spec',
  'specs',
  'testdata',
  'test-utils',
  'test-helpers',
  '__fixtures__',
  '__test__',
  '__mocks__',
  'mocks',
  'benchmark',
  'benchmarks',
]);
const exampleSegments = new Set(['example', 'examples', 'storybook', '.storybook', 'stories']);
export const snapshotLimits = {
  files: 1500,
  bytesPerFile: 512 * 1024,
  lockfileBytes: 4 * 1024 * 1024,
  totalBytes: 8 * 1024 * 1024,
};
async function projectIgnore(root: string) {
  const matcher = ignore();
  try {
    matcher.add(await readFile(path.join(root, '.gitignore'), 'utf8'));
  } catch {
    /* Missing or unreadable ignore rules safely result in scanning more files. */
  }
  return matcher;
}
function ignoredByProject(
  matcher: ReturnType<typeof ignore>,
  root: string,
  absolute: string,
  directory: boolean,
): boolean {
  const relative = path.relative(root, absolute).split(path.sep).join('/');
  return Boolean(relative) && matcher.ignores(directory ? `${relative}/` : relative);
}
const dependencyLockfiles = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
]);
const coverageArtifactPaths = ['coverage/coverage-summary.json', 'coverage/lcov.info'] as const;
const environmentTemplateName = /^\.env(?:\.[A-Za-z0-9_-]+)*\.(?:example|sample|template)$/i;
function isEnvironmentTemplate(name: string): boolean {
  return environmentTemplateName.test(name);
}
function sanitizeEnvironmentTemplate(content: string): string {
  const names = new Set<string>();
  for (const line of content.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (match?.[1]) names.add(match[1]);
  }
  return names.size ? `${[...names].map((name) => `${name}=`).join('\n')}\n` : '';
}
function fileByteLimit(name: string): number {
  return dependencyLockfiles.has(name) ? snapshotLimits.lockfileBytes : snapshotLimits.bytesPerFile;
}
function fileExclusion(name: string): 'sensitive-file' | 'unsupported-file' | null {
  if (
    (name.startsWith('.env') && !isEnvironmentTemplate(name)) ||
    /\.(pem|key|p12|pfx)$/i.test(name)
  )
    return 'sensitive-file';
  if (
    excludedFiles.has(name) ||
    (!extensions.has(path.extname(name)) &&
      name !== 'Dockerfile' &&
      name !== 'yarn.lock' &&
      !isEnvironmentTemplate(name))
  )
    return 'unsupported-file';
  return null;
}
export function classifySourceScope(relativePath: string): SourceScope {
  const normalized = relativePath.replaceAll('\\', '/').toLowerCase();
  const segments = normalized.split('/');
  const file = segments.at(-1) ?? '';
  if (
    segments.some((segment) => testSegments.has(segment)) ||
    /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(file) ||
    /(?:^test-|-(?:test|spec)-(?:helpers?|fixtures?|harness))[^/]*\.[cm]?[jt]sx?$/.test(file)
  )
    return 'test';
  if (
    segments.some((segment) => exampleSegments.has(segment)) ||
    /\.stories\.[cm]?[jt]sx?$/.test(file)
  )
    return 'example';
  return 'runtime';
}
export function isRuntimeSource(file: { scope?: SourceScope }): boolean {
  return !file.scope || file.scope === 'runtime';
}
function scopeOrder(directory: string, entryName: string, root: string): number {
  return classifySourceScope(path.relative(root, path.join(directory, entryName))) === 'runtime'
    ? 0
    : 1;
}
export function isWithin(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return (
    relative === '' ||
    (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))
  );
}
export function safeRelative(value: string): string {
  const normalized = value.replaceAll('\\', '/');
  if (
    !normalized ||
    normalized.includes('\0') ||
    /^[a-z]:/i.test(normalized) ||
    normalized.startsWith('/') ||
    normalized.split('/').some((part) => part === '..' || part === '.')
  ) {
    throw new Error('Unsafe relative path.');
  }
  return normalized;
}
export async function validateProjectRoot(input: string, dataDirectory: string): Promise<string> {
  const root = await realpath(path.resolve(input));
  const metadata = await lstat(root);
  if (!metadata.isDirectory()) throw new Error('The project must be a directory.');
  const home = await realpath(os.homedir());
  if (root === path.parse(root).root || root === home)
    throw new Error('Register a project, not the filesystem root or home directory.');
  const data = path.resolve(dataDirectory);
  if (isWithin(root, data) || isWithin(data, root))
    throw new Error(
      'Project and audit storage must not overlap. Move TRACEWARD_DATA_DIR outside the repository.',
    );
  return root;
}
export async function estimateProjectScope(root: string): Promise<ProjectScopeEstimate> {
  const canonicalRoot = await realpath(root);
  const ignoreRules = await projectIgnore(canonicalRoot);
  const reasons = new Set<string>();
  let supportedFiles = 0;
  let supportedBytes = 0;
  const scopeFiles: Record<SourceScope, number> = { runtime: 0, test: 0, example: 0 };
  let oversizedFiles = 0;
  let visitedEntries = 0;
  let stopped = false;
  async function walk(directory: string, depth: number): Promise<void> {
    if (stopped) return;
    if (depth > 24) {
      reasons.add('depth-limit');
      return;
    }
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      reasons.add('unreadable-entry');
      return;
    }
    entries.sort(
      (a, b) =>
        scopeOrder(directory, a.name, canonicalRoot) -
          scopeOrder(directory, b.name, canonicalRoot) || a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (++visitedEntries > 12_000) {
        reasons.add('entry-limit');
        stopped = true;
        return;
      }
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (
          ignoredDirectories.has(entry.name) ||
          ignoredByProject(ignoreRules, canonicalRoot, absolute, true)
        )
          continue;
        try {
          const resolved = await realpath(absolute);
          if (isWithin(canonicalRoot, resolved)) await walk(absolute, depth + 1);
        } catch {
          reasons.add('unreadable-entry');
        }
        continue;
      }
      if (
        !entry.isFile() ||
        fileExclusion(entry.name) ||
        ignoredByProject(ignoreRules, canonicalRoot, absolute, false)
      )
        continue;
      try {
        const resolved = await realpath(absolute);
        const metadata = await lstat(absolute);
        if (!isWithin(canonicalRoot, resolved) || !metadata.isFile()) continue;
        supportedFiles++;
        supportedBytes += metadata.size;
        scopeFiles[classifySourceScope(path.relative(canonicalRoot, absolute))]++;
        if (metadata.size > fileByteLimit(entry.name)) oversizedFiles++;
      } catch {
        reasons.add('unreadable-entry');
      }
    }
  }
  await walk(canonicalRoot, 0);
  for (const relative of coverageArtifactPaths) {
    const absolute = path.join(/* turbopackIgnore: true */ canonicalRoot, relative);
    try {
      const resolved = await realpath(/* turbopackIgnore: true */ absolute);
      const metadata = await lstat(absolute);
      if (!isWithin(canonicalRoot, resolved) || !metadata.isFile()) continue;
      supportedFiles++;
      supportedBytes += metadata.size;
      scopeFiles.test++;
      if (metadata.size > snapshotLimits.bytesPerFile) oversizedFiles++;
    } catch {
      // Coverage artifacts are optional.
    }
  }
  if (supportedFiles > snapshotLimits.files) reasons.add('file-count-limit');
  if (supportedBytes > snapshotLimits.totalBytes) reasons.add('total-byte-limit');
  if (oversizedFiles) reasons.add('per-file-byte-limit');
  return {
    schemaVersion: 1,
    estimatedAt: new Date().toISOString(),
    supportedFiles,
    supportedBytes,
    scopeFiles,
    oversizedFiles,
    visitedEntries,
    predictedTruncated: reasons.size > 0,
    reasons: [...reasons].sort(),
    limits: { ...snapshotLimits },
  };
}
export async function captureSnapshot(root: string): Promise<Snapshot> {
  const ignoreRules = await projectIgnore(root);
  const files: SourceFile[] = [];
  const skipped: Record<string, number> = {};
  let totalBytes = 0;
  let truncated = false;
  let visited = 0;
  const skip = (reason: string) => {
    skipped[reason] = (skipped[reason] ?? 0) + 1;
  };
  async function walk(directory: string, depth: number): Promise<void> {
    if (depth > 24) {
      skip('depth-limit');
      truncated = true;
      return;
    }
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort(
      (a, b) =>
        scopeOrder(directory, a.name, root) - scopeOrder(directory, b.name, root) ||
        a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (
        ++visited > 12000 ||
        files.length >= snapshotLimits.files ||
        totalBytes >= snapshotLimits.totalBytes
      ) {
        truncated = true;
        skip('budget-limit');
        return;
      }
      if (entry.isSymbolicLink()) {
        skip('symbolic-link');
        continue;
      }
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (ignoredDirectories.has(entry.name)) {
          skip('excluded-directory');
          continue;
        }
        if (ignoredByProject(ignoreRules, root, absolute, true)) {
          skip('gitignored-path');
          continue;
        }
        const resolved = await realpath(absolute);
        if (!isWithin(root, resolved)) {
          skip('outside-project');
          continue;
        }
        await walk(absolute, depth + 1);
        continue;
      }
      if (!entry.isFile()) {
        skip('special-file');
        continue;
      }
      if (ignoredByProject(ignoreRules, root, absolute, false)) {
        skip('gitignored-path');
        continue;
      }
      const exclusion = fileExclusion(entry.name);
      if (exclusion) {
        skip(exclusion);
        continue;
      }
      try {
        const resolved = await realpath(absolute);
        if (!isWithin(root, resolved)) {
          skip('outside-project');
          continue;
        }
        const handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        try {
          const stat = await handle.stat();
          const byteLimit = fileByteLimit(entry.name);
          if (
            !stat.isFile() ||
            stat.size > byteLimit ||
            totalBytes + stat.size > snapshotLimits.totalBytes
          ) {
            skip('file-size-limit');
            truncated = true;
            continue;
          }
          const buffer = Buffer.alloc(Math.min(stat.size + 1, byteLimit + 1));
          const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
          if (bytesRead !== stat.size || bytesRead > byteLimit) {
            skip('changed-during-read');
            truncated = true;
            continue;
          }
          const rawContent = buffer.subarray(0, bytesRead).toString('utf8');
          if (rawContent.includes('\0')) {
            skip('binary-file');
            continue;
          }
          const content = isEnvironmentTemplate(entry.name)
            ? sanitizeEnvironmentTemplate(rawContent)
            : rawContent;
          files.push({
            path: safeRelative(path.relative(root, absolute)),
            scope: classifySourceScope(path.relative(root, absolute)),
            content,
            digest: digest(content),
            bytes: Buffer.byteLength(content),
          });
          totalBytes += bytesRead;
        } finally {
          await handle.close();
        }
      } catch {
        skip('unreadable-file');
        truncated = true;
      }
    }
  }
  await walk(root, 0);
  for (const relative of coverageArtifactPaths) {
    if (
      files.some((file) => file.path === relative) ||
      files.length >= snapshotLimits.files ||
      totalBytes >= snapshotLimits.totalBytes
    )
      continue;
    const absolute = path.join(/* turbopackIgnore: true */ root, relative);
    try {
      const resolved = await realpath(/* turbopackIgnore: true */ absolute);
      if (!isWithin(root, resolved)) continue;
      const handle = await open(
        /* turbopackIgnore: true */ absolute,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
      );
      try {
        const metadata = await handle.stat();
        if (
          !metadata.isFile() ||
          metadata.size > snapshotLimits.bytesPerFile ||
          totalBytes + metadata.size > snapshotLimits.totalBytes
        ) {
          skip('coverage-artifact-size-limit');
          truncated = true;
          continue;
        }
        const buffer = Buffer.alloc(metadata.size + 1);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        if (bytesRead !== metadata.size || bytesRead > snapshotLimits.bytesPerFile) {
          skip('changed-during-read');
          truncated = true;
          continue;
        }
        const content = buffer.subarray(0, bytesRead).toString('utf8');
        if (content.includes('\0')) continue;
        files.push({
          path: relative,
          scope: 'test',
          content,
          digest: digest(content),
          bytes: bytesRead,
        });
        totalBytes += bytesRead;
      } finally {
        await handle.close();
      }
    } catch {
      // Coverage artifacts are optional.
    }
  }
  return {
    files,
    totalBytes,
    skipped,
    truncated,
    digest: digest(files.map((file) => `${file.path}:${file.digest}`).join('\n')),
  };
}
export function redactedSnapshot(snapshot: Snapshot): Snapshot {
  return {
    ...snapshot,
    files: snapshot.files.map((file) => ({ ...file, content: redact(file.content) })),
  };
}
