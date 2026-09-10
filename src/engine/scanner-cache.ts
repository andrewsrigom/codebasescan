import { createHash, randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, readdir, rename, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import type { ScannerRun } from '../domain/types.ts';
import { auditWorkflowVersion } from '../domain/versions.ts';

const scannerCacheSchemaVersion = 1 as const;
const maximumCacheEntryBytes = 12 * 1024 * 1024;
const maximumCacheBytes = 256 * 1024 * 1024;
const maximumCacheEntries = 256;
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const cacheEnvelope = z.object({
  schemaVersion: z.literal(scannerCacheSchemaVersion),
  key: digest,
  snapshotDigest: digest,
  scannerId: z.string().min(1).max(100),
  scannerVersion: z.string().min(1).max(100),
  workflowVersion: z.string().min(1).max(100),
  variant: z.string().max(200),
  storedAt: z.iso.datetime({ offset: true }),
  value: z.unknown(),
});

export interface ScannerCacheOptions {
  directory: string;
  enabled: boolean;
}

export interface CachedScanOptions {
  snapshotDigest: string;
  scannerId: string;
  scannerVersion: string;
  expectedRunIds: string[];
  variant?: string;
}

function cacheKey(options: CachedScanOptions): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        schemaVersion: scannerCacheSchemaVersion,
        snapshotDigest: options.snapshotDigest,
        scannerId: options.scannerId,
        scannerVersion: options.scannerVersion,
        workflowVersion: auditWorkflowVersion,
        variant: options.variant ?? '',
      }),
    )
    .digest('hex');
}

function scannerRuns(value: unknown): ScannerRun[] {
  if (!value || typeof value !== 'object') return [];
  const record = value as Record<string, unknown>;
  if (Array.isArray(record.scanners)) return record.scanners as ScannerRun[];
  if (Array.isArray(record.runs)) return record.runs as ScannerRun[];
  return record.run ? [record.run as ScannerRun] : [];
}

function validScannerRun(value: unknown): value is ScannerRun {
  if (!value || typeof value !== 'object') return false;
  const run = value as Partial<ScannerRun>;
  return (
    typeof run.id === 'string' &&
    typeof run.name === 'string' &&
    ['completed', 'partial', 'skipped', 'failed'].includes(run.status ?? '') &&
    typeof run.durationMs === 'number' &&
    Number.isFinite(run.durationMs) &&
    run.durationMs >= 0 &&
    typeof run.findings === 'number' &&
    Number.isSafeInteger(run.findings) &&
    run.findings >= 0 &&
    typeof run.detail === 'string'
  );
}

function hasExpectedRuns(value: unknown, expectedRunIds: string[]): boolean {
  const actual = scannerRuns(value);
  return (
    actual.length === expectedRunIds.length &&
    actual.every(validScannerRun) &&
    [...actual.map((run) => run.id)].sort().join('\0') === [...expectedRunIds].sort().join('\0')
  );
}

function annotate<T>(value: T, metadata: NonNullable<ScannerRun['cache']>, durationMs?: number): T {
  const copy = structuredClone(value);
  for (const run of scannerRuns(copy)) {
    const sourceDurationMs = run.durationMs;
    if (durationMs !== undefined) run.durationMs = durationMs;
    run.cache = {
      ...metadata,
      ...(durationMs !== undefined ? { sourceDurationMs } : {}),
    };
  }
  return copy;
}

async function readEntry(
  directory: string,
  key: string,
  options: CachedScanOptions,
): Promise<{ storedAt: string; value: unknown } | null> {
  try {
    const file = path.join(directory, `${key}.json`);
    const metadata = await stat(file);
    if (!metadata.isFile() || metadata.size > maximumCacheEntryBytes) return null;
    const parsed = cacheEnvelope.parse(JSON.parse(await readFile(file, 'utf8')) as unknown);
    if (
      parsed.key !== key ||
      parsed.snapshotDigest !== options.snapshotDigest ||
      parsed.scannerId !== options.scannerId ||
      parsed.scannerVersion !== options.scannerVersion ||
      parsed.workflowVersion !== auditWorkflowVersion ||
      parsed.variant !== (options.variant ?? '') ||
      !hasExpectedRuns(parsed.value, options.expectedRunIds)
    )
      return null;
    return { storedAt: parsed.storedAt, value: parsed.value };
  } catch {
    return null;
  }
}

async function writeEntry(
  directory: string,
  key: string,
  options: CachedScanOptions,
  value: unknown,
  storedAt: string,
): Promise<boolean> {
  if (!hasExpectedRuns(value, options.expectedRunIds)) return false;
  const serialized = `${JSON.stringify({
    schemaVersion: scannerCacheSchemaVersion,
    key,
    snapshotDigest: options.snapshotDigest,
    scannerId: options.scannerId,
    scannerVersion: options.scannerVersion,
    workflowVersion: auditWorkflowVersion,
    variant: options.variant ?? '',
    storedAt,
    value,
  })}\n`;
  if (Buffer.byteLength(serialized) > maximumCacheEntryBytes) return false;
  let temporary = '';
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    temporary = path.join(directory, `${key}.${randomUUID()}.tmp`);
    await writeFile(temporary, serialized, { mode: 0o600, flag: 'wx' });
    const destination = path.join(directory, `${key}.json`);
    await rename(temporary, destination);
    temporary = '';
    await chmod(destination, 0o600);
    await pruneScannerCache(directory);
    return true;
  } catch {
    if (temporary) await unlink(temporary).catch(() => undefined);
    return false;
  }
}

async function pruneScannerCache(directory: string): Promise<void> {
  try {
    const names = (await readdir(directory))
      .filter((name) => /^[a-f0-9]{64}\.json$/.test(name))
      .slice(0, 10_000);
    const entries = (
      await Promise.all(
        names.map(async (name) => {
          const metadata = await stat(path.join(directory, name));
          return { name, bytes: metadata.size, modifiedAt: metadata.mtimeMs };
        }),
      )
    ).sort(
      (left, right) => right.modifiedAt - left.modifiedAt || left.name.localeCompare(right.name),
    );
    let retainedBytes = 0;
    for (const [index, entry] of entries.entries()) {
      retainedBytes += entry.bytes;
      if (index < maximumCacheEntries && retainedBytes <= maximumCacheBytes) continue;
      await unlink(path.join(directory, entry.name)).catch(() => undefined);
    }
  } catch {
    // Cache maintenance is best effort and can never fail an audit.
  }
}

export async function runCachedScan<T>(
  cache: ScannerCacheOptions,
  options: CachedScanOptions,
  execute: () => Promise<T> | T,
): Promise<T> {
  if (!cache.enabled) return execute();
  const key = cacheKey(options);
  const started = performance.now();
  const hit = await readEntry(cache.directory, key, options);
  if (hit)
    return annotate(
      hit.value as T,
      {
        status: 'hit',
        key,
        storedAt: hit.storedAt,
      },
      Math.max(0, Math.round(performance.now() - started)),
    );

  const value = await execute();
  const storedAt = new Date().toISOString();
  const stored = await writeEntry(cache.directory, key, options, value, storedAt);
  return annotate(value, {
    status: 'miss',
    key,
    ...(stored ? { storedAt } : {}),
  });
}

export const scannerCacheLimits = {
  schemaVersion: scannerCacheSchemaVersion,
  maximumEntryBytes: maximumCacheEntryBytes,
  maximumBytes: maximumCacheBytes,
  maximumEntries: maximumCacheEntries,
} as const;
