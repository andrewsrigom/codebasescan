import path from 'node:path';
import os from 'node:os';
import { constants } from 'node:fs';
import { lstat, open, realpath, readdir } from 'node:fs/promises';
import { digest } from '../domain/findings.ts';
import type { Snapshot, SourceFile } from '../domain/types.ts';
import { redact } from './redact.ts';
const ignoredDirectories = new Set(['.git', 'node_modules', '.next', 'dist', 'build', 'coverage', '.traceward', '.turbo', '.venv', 'vendor']);
const extensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json', '.yaml', '.yml', '.toml', '.sql']);
const excludedFiles = new Set(['.gitleaks.toml', '.semgrepignore', '.semgrep.yml', '.semgrep.yaml']);
export const snapshotLimits = { files: 1500, bytesPerFile: 256 * 1024, totalBytes: 8 * 1024 * 1024 };
export function isWithin(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}
export function safeRelative(value: string): string {
  const normalized = value.replaceAll('\\', '/');
  if (!normalized || normalized.includes('\0') || /^[a-z]:/i.test(normalized) || normalized.startsWith('/') || normalized.split('/').some((part) => part === '..' || part === '.')) {
    throw new Error('Unsafe relative path.');
  }
  return normalized;
}
export async function validateProjectRoot(input: string, dataDirectory: string): Promise<string> {
  const root = await realpath(path.resolve(input));
  const metadata = await lstat(root);
  if (!metadata.isDirectory())
    throw new Error('The project must be a directory.');
  const home = await realpath(os.homedir());
  if (root === path.parse(root).root || root === home)
    throw new Error('Register a project, not the filesystem root or home directory.');
  const data = path.resolve(dataDirectory);
  if (isWithin(root, data) || isWithin(data, root))
    throw new Error('Project and audit storage must not overlap. Move TRACEWARD_DATA_DIR outside the repository.');
  return root;
}
export async function captureSnapshot(root: string): Promise<Snapshot> {
  const files: SourceFile[] = [];
  const skipped: Record<string, number> = {};
  let totalBytes = 0;
  let truncated = false;
  let visited = 0;
  const skip = (reason: string) => { skipped[reason] = (skipped[reason] ?? 0) + 1; };
  async function walk(directory: string, depth: number): Promise<void> {
    if (depth > 24) {
      skip('depth-limit');
      truncated = true;
      return;
    }
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (++visited > 12000 || files.length >= snapshotLimits.files || totalBytes >= snapshotLimits.totalBytes) {
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
      if (entry.name.startsWith('.env') || /\.(pem|key|p12|pfx)$/i.test(entry.name)) {
        skip('sensitive-file');
        continue;
      }
      if (excludedFiles.has(entry.name) || (!extensions.has(path.extname(entry.name)) && entry.name !== 'Dockerfile')) {
        skip('unsupported-file');
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
          if (!stat.isFile() || stat.size > snapshotLimits.bytesPerFile || totalBytes + stat.size > snapshotLimits.totalBytes) {
            skip('file-size-limit');
            truncated = true;
            continue;
          }
          const buffer = Buffer.alloc(Math.min(stat.size + 1, snapshotLimits.bytesPerFile + 1));
          const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
          if (bytesRead !== stat.size || bytesRead > snapshotLimits.bytesPerFile) {
            skip('changed-during-read');
            truncated = true;
            continue;
          }
          const content = buffer.subarray(0, bytesRead).toString('utf8');
          if (content.includes('\0')) {
            skip('binary-file');
            continue;
          }
          files.push({ path: safeRelative(path.relative(root, absolute)), content, digest: digest(content), bytes: bytesRead });
          totalBytes += bytesRead;
        }
        finally {
          await handle.close();
        }
      }
      catch {
        skip('unreadable-file');
        truncated = true;
      }
    }
  }
  await walk(root, 0);
  return { files, totalBytes, skipped, truncated, digest: digest(files.map((file) => `${file.path}:${file.digest}`).join('\n')) };
}
export function redactedSnapshot(snapshot: Snapshot): Snapshot {
  return { ...snapshot, files: snapshot.files.map((file) => ({ ...file, content: redact(file.content) })) };
}
