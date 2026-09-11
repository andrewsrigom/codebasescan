import path from 'node:path';
import { lstat, readFile, writeFile } from 'node:fs/promises';

export const projectConfigFileName = 'codebasescan.config.json';

type PackageManager = 'npm' | 'pnpm' | 'yarn';

interface PackageManifest {
  packageManager?: unknown;
  scripts?: unknown;
}

async function regularFile(file: string): Promise<boolean> {
  try {
    const metadata = await lstat(file);
    return metadata.isFile() && !metadata.isSymbolicLink();
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return false;
    throw error;
  }
}

async function packageManifest(root: string): Promise<PackageManifest> {
  const file = path.join(root, 'package.json');
  if (!(await regularFile(file))) return {};
  const metadata = await lstat(file);
  if (metadata.size > 1024 * 1024) return {};
  try {
    const value: unknown = JSON.parse(await readFile(file, 'utf8'));
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as PackageManifest)
      : {};
  } catch {
    return {};
  }
}

async function detectPackageManager(
  root: string,
  manifest: PackageManifest,
): Promise<PackageManager> {
  if (typeof manifest.packageManager === 'string') {
    const declared = manifest.packageManager.split('@')[0];
    if (declared === 'npm' || declared === 'pnpm' || declared === 'yarn') return declared;
  }
  if (await regularFile(path.join(root, 'pnpm-lock.yaml'))) return 'pnpm';
  if (await regularFile(path.join(root, 'yarn.lock'))) return 'yarn';
  return 'npm';
}

function declaredScripts(manifest: PackageManifest, candidates: string[]): string[] {
  if (!manifest.scripts || typeof manifest.scripts !== 'object' || Array.isArray(manifest.scripts))
    return [];
  const scripts = manifest.scripts as Record<string, unknown>;
  return candidates.filter((name) => typeof scripts[name] === 'string');
}

export async function initializeProjectConfig(project = '.', force = false): Promise<string> {
  const root = path.resolve(project);
  const rootMetadata = await lstat(root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink())
    throw new Error('Init target must be a regular project directory.');
  const manifest = await packageManifest(root);
  const config = {
    $schema: './node_modules/codebasescan/configs/codebasescan.config.schema.json',
    schemaVersion: 1,
    context: {
      features: [],
      roles: [],
      sensitiveData: [],
      storageBoundaries: [],
      externalServices: [],
      priorityPaths: [],
      outOfScopePaths: [],
    },
    expectedUnauthenticatedRoutes: [],
    verification: {
      packageManager: await detectPackageManager(root, manifest),
      testScripts: declaredScripts(manifest, ['test', 'test:unit', 'test:integration', 'test:e2e']),
      buildScripts: declaredScripts(manifest, ['build']),
    },
  };
  const destination = path.join(root, projectConfigFileName);
  try {
    await writeFile(destination, `${JSON.stringify(config, null, 2)}\n`, {
      mode: 0o600,
      flag: force ? 'w' : 'wx',
    });
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'EEXIST')
      throw new Error(`Configuration already exists: ${destination}. Use --force to replace it.`);
    throw error;
  }
  return destination;
}
