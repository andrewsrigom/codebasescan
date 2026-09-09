import path from 'node:path';
import { chmod, mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type {
  Dependency,
  Evidence,
  Finding,
  ScannerRun,
  Severity,
  Snapshot,
} from '../domain/types.ts';
import { digest, makeFinding } from '../domain/findings.ts';
import { redact } from '../security/redact.ts';
import { resolvedInventory } from './inventory.ts';

const batchSchema = z.object({
  results: z.array(
    z.object({
      vulns: z.array(z.object({ id: z.string().min(1).max(100) })).optional(),
      next_page_token: z.string().optional(),
    }),
  ),
});
const recordSchema = z.object({
  id: z.string().min(1).max(100),
  modified: z.string().max(100).optional(),
  withdrawn: z.string().max(100).optional(),
  summary: z.string().max(5000).optional(),
  aliases: z.array(z.string().max(100)).max(100).optional(),
  severity: z
    .array(z.object({ type: z.string().max(50), score: z.string().max(500) }))
    .max(20)
    .optional(),
  affected: z
    .array(
      z.object({
        package: z.object({ name: z.string().max(214) }),
        severity: z
          .array(z.object({ type: z.string().max(50), score: z.string().max(500) }))
          .max(20)
          .optional(),
        ranges: z
          .array(
            z.object({
              events: z
                .array(
                  z.object({
                    fixed: z.string().max(200).optional(),
                  }),
                )
                .max(10000),
            }),
          )
          .max(1000)
          .optional(),
        ecosystem_specific: z.record(z.string(), z.unknown()).optional(),
        database_specific: z.record(z.string(), z.unknown()).optional(),
      }),
    )
    .max(1000)
    .optional(),
  database_specific: z.record(z.string(), z.unknown()).optional(),
});

interface CompactRecord {
  id: string;
  modified?: string;
  withdrawn?: string;
  summary: string;
  aliases: string[];
  severity: { type: string; score: string }[];
  packages: {
    name: string;
    fixedVersions: string[];
    ecosystemSeverity?: string;
  }[];
  databaseSeverity?: string;
}

interface CacheEntry {
  fetchedAt: string;
  vulnerabilities: CompactRecord[];
}

interface CacheFile {
  schemaVersion: 1;
  entries: Record<string, CacheEntry>;
}

const compactRecordSchema = z.object({
  id: z.string().min(1).max(100),
  modified: z.string().max(100).optional(),
  withdrawn: z.string().max(100).optional(),
  summary: z.string().max(800),
  aliases: z.array(z.string().max(100)).max(30),
  severity: z.array(z.object({ type: z.string().max(50), score: z.string().max(500) })).max(20),
  packages: z
    .array(
      z.object({
        name: z.string().max(214),
        fixedVersions: z.array(z.string().max(200)).max(30),
        ecosystemSeverity: z.string().max(50).optional(),
      }),
    )
    .max(1000),
  databaseSeverity: z.string().max(50).optional(),
});

const cacheSchema = z.object({
  schemaVersion: z.literal(1),
  entries: z.record(
    z.string().max(500),
    z.object({
      fetchedAt: z.string().max(100),
      vulnerabilities: z.array(compactRecordSchema).max(300),
    }),
  ),
});

export interface OsvScanResult {
  dependencies: Dependency[];
  findings: Finding[];
  run: ScannerRun;
}

export interface OsvRuntime {
  fetch?: typeof fetch;
  now?: () => number;
}

function compact(value: unknown): CompactRecord {
  const item = recordSchema.parse(value);
  const databaseSeverity = item.database_specific?.severity;
  return {
    id: item.id,
    ...(item.modified ? { modified: item.modified } : {}),
    ...(item.withdrawn ? { withdrawn: item.withdrawn } : {}),
    summary: redact(item.summary ?? 'Known vulnerability reported by OSV').slice(0, 800),
    aliases: [...new Set(item.aliases ?? [])].slice(0, 30),
    severity: item.severity ?? [],
    packages: (item.affected ?? []).map((affected) => ({
      name: affected.package.name,
      fixedVersions: [
        ...new Set(
          (affected.ranges ?? []).flatMap((range) =>
            range.events.flatMap((event) => (event.fixed ? [event.fixed] : [])),
          ),
        ),
      ].slice(0, 30),
      ...(typeof affected.ecosystem_specific?.severity === 'string'
        ? { ecosystemSeverity: affected.ecosystem_specific.severity.slice(0, 50) }
        : typeof affected.database_specific?.severity === 'string'
          ? { ecosystemSeverity: affected.database_specific.severity.slice(0, 50) }
          : {}),
    })),
    ...(typeof databaseSeverity === 'string'
      ? { databaseSeverity: databaseSeverity.slice(0, 50) }
      : {}),
  };
}

function consolidate(records: CompactRecord[]): CompactRecord[] {
  const groups: CompactRecord[] = [];
  for (const record of records.filter((item) => !item.withdrawn)) {
    const identifiers = new Set([record.id, ...record.aliases]);
    const index = groups.findIndex((candidate) =>
      [candidate.id, ...candidate.aliases].some((id) => identifiers.has(id)),
    );
    if (index < 0) {
      groups.push(record);
      continue;
    }
    const existing = groups[index]!;
    const packageRecords = new Map(existing.packages.map((item) => [item.name, item]));
    for (const item of record.packages) {
      const previous = packageRecords.get(item.name);
      packageRecords.set(item.name, {
        name: item.name,
        fixedVersions: [...new Set([...(previous?.fixedVersions ?? []), ...item.fixedVersions])],
        ...(previous?.ecosystemSeverity || item.ecosystemSeverity
          ? { ecosystemSeverity: previous?.ecosystemSeverity ?? item.ecosystemSeverity }
          : {}),
      });
    }
    groups[index] = {
      ...existing,
      aliases: [
        ...new Set(
          [...existing.aliases, record.id, ...record.aliases].filter((id) => id !== existing.id),
        ),
      ],
      severity: [
        ...new Map(
          [...existing.severity, ...record.severity].map((item) => [
            `${item.type}:${item.score}`,
            item,
          ]),
        ).values(),
      ],
      packages: [...packageRecords.values()],
      ...(record.modified && (!existing.modified || record.modified > existing.modified)
        ? { modified: record.modified }
        : {}),
    };
  }
  return groups;
}

async function boundedJson(response: Response, maximum = 4 * 1024 * 1024): Promise<unknown> {
  if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}.`);
  const length = Number(response.headers.get('content-length') ?? 0);
  if (length > maximum) throw new Error('OSV response exceeded the size limit.');
  if (!response.body) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.length;
    if (bytes > maximum) {
      await reader.cancel();
      throw new Error('OSV response exceeded the size limit.');
    }
    chunks.push(value);
  }
  const body = Buffer.concat(chunks).toString('utf8');
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new Error('OSV returned malformed JSON.');
  }
}

async function osvFetch(
  fetcher: typeof fetch,
  url: string,
  init: RequestInit,
  signal?: AbortSignal,
): Promise<unknown> {
  const deadline = AbortSignal.timeout(10000);
  const requestSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const response = await fetcher(url, { ...init, signal: requestSignal });
      if ((response.status === 429 || response.status >= 500) && attempt === 0) continue;
      return await boundedJson(response);
    } catch (error) {
      lastError = error;
      if (attempt === 1 || requestSignal.aborted) break;
    }
  }
  throw lastError instanceof Error ? lastError : new Error('OSV request failed.');
}

async function readCache(cachePath: string): Promise<CacheFile> {
  try {
    const metadata = await stat(cachePath);
    if (metadata.size > 8 * 1024 * 1024) return { schemaVersion: 1, entries: {} };
    const cache = cacheSchema.parse(JSON.parse(await readFile(cachePath, 'utf8')) as unknown);
    if (Object.keys(cache.entries).length > 5000) return { schemaVersion: 1, entries: {} };
    return cache;
  } catch {
    return { schemaVersion: 1, entries: {} };
  }
}

async function saveCache(cachePath: string, cache: CacheFile): Promise<void> {
  await mkdir(path.dirname(cachePath), { recursive: true, mode: 0o700 });
  const temporary = `${cachePath}.${randomUUID()}.tmp`;
  await writeFile(temporary, JSON.stringify(cache), { mode: 0o600, flag: 'wx' });
  await rename(temporary, cachePath);
  await chmod(cachePath, 0o600);
}

function cacheKey(dependency: Dependency): string {
  return `npm:${dependency.name}@${dependency.resolvedVersion}`;
}

function severity(record: CompactRecord, packageName: string): Severity {
  const packageSeverity = record.packages.find(
    (item) => item.name === packageName,
  )?.ecosystemSeverity;
  const label = (packageSeverity ?? record.databaseSeverity ?? '').toUpperCase();
  if (label.includes('CRITICAL')) return 'critical';
  if (label.includes('HIGH')) return 'high';
  if (label.includes('LOW')) return 'low';
  return 'medium';
}

function dependencyEvidence(
  snapshot: Snapshot,
  dependency: Dependency,
  record: CompactRecord,
): Evidence {
  const lockfile = snapshot.files.find((file) => file.path === dependency.lockfile);
  const line = dependency.lockfileLine ?? 1;
  const observation = `${record.id} affects ${dependency.name}@${dependency.resolvedVersion}. Presence does not establish reachability or exploitability.`;
  return {
    id: digest(`${dependency.lockfile}:${line}:${observation}`).slice(0, 16),
    kind: 'dependency',
    file: dependency.lockfile ?? dependency.manifest,
    startLine: line,
    endLine: line,
    excerpt: `${dependency.name}@${dependency.resolvedVersion}`,
    fileDigest: lockfile?.digest ?? digest(dependency.manifest),
    observation,
  };
}

function normalize(snapshot: Snapshot, dependency: Dependency, record: CompactRecord): Finding {
  const affected = record.packages.find((item) => item.name === dependency.name);
  const fixedVersions = affected?.fixedVersions ?? [];
  const normalizedSeverity = severity(record, dependency.name);
  const originalSeverity =
    affected?.ecosystemSeverity ??
    record.databaseSeverity ??
    record.severity.map((item) => `${item.type}:${item.score}`).join(', ');
  const finding = makeFinding({
    source: 'osv',
    ruleId: record.id,
    title: record.summary || `Known vulnerability in ${dependency.name}`,
    category: 'dependencies',
    severity: normalizedSeverity,
    sourceSeverity: originalSeverity || 'UNSPECIFIED',
    description: `OSV reports ${dependency.name}@${dependency.resolvedVersion} as affected. The dependency is ${dependency.relationship ?? 'unknown'} in the captured lockfile; runtime reachability and exploitability were not assessed.`,
    remediation: fixedVersions.length
      ? `Evaluate an upgrade to a non-affected release. OSV records fixed version(s): ${fixedVersions.join(', ')}.`
      : 'Review the advisory and supported upgrade path. No fixed version was present in the returned OSV record.',
    cwe: [],
    evidence: [dependencyEvidence(snapshot, dependency, record)],
  });
  finding.vulnerability = {
    id: record.id,
    aliases: record.aliases,
    package: dependency.name,
    version: dependency.resolvedVersion ?? '',
    fixedVersions,
    severity: record.severity,
    relationship: dependency.relationship ?? 'unknown',
    lockfile: dependency.lockfile ?? dependency.manifest,
    ...(record.modified ? { advisoryModified: record.modified } : {}),
  };
  return finding;
}

export async function scanOsv(
  snapshot: Snapshot,
  enabled: boolean,
  cachePath: string,
  cacheHours: number,
  signal?: AbortSignal,
  runtime: OsvRuntime = {},
): Promise<OsvScanResult> {
  const started = Date.now();
  const inventory = resolvedInventory(snapshot);
  const resolved = inventory.dependencies
    .filter((item) => item.resolvedVersion && item.lockfile)
    .slice(0, 1000);
  if (!enabled)
    return {
      dependencies: inventory.dependencies,
      findings: [],
      run: {
        id: 'osv',
        name: 'Dependency vulnerabilities',
        status: 'skipped',
        durationMs: Date.now() - started,
        findings: 0,
        detail: `OSV network lookup is disabled. ${resolved.length} resolved lockfile package(s) were inventoried locally.`,
        version: 'API v1',
      },
    };
  if (!resolved.length)
    return {
      dependencies: inventory.dependencies,
      findings: [],
      run: {
        id: 'osv',
        name: 'Dependency vulnerabilities',
        status: inventory.errors.length ? 'failed' : 'skipped',
        durationMs: Date.now() - started,
        findings: 0,
        detail: inventory.errors.length
          ? 'A supported lockfile was malformed; no clean dependency result is implied.'
          : 'No resolved npm, pnpm, or Yarn lockfile packages were available. Declared ranges were not queried.',
        version: 'API v1',
      },
    };
  const fetcher = runtime.fetch ?? fetch;
  const clock = runtime.now ?? Date.now;
  const cache = await readCache(cachePath);
  const records = new Map<string, CompactRecord[]>();
  const missing: Dependency[] = [];
  const freshAfter = clock() - cacheHours * 60 * 60 * 1000;
  for (const item of resolved) {
    const entry = cache.entries[cacheKey(item)];
    if (entry && Date.parse(entry.fetchedAt) >= freshAfter)
      records.set(cacheKey(item), consolidate(entry.vulnerabilities));
    else missing.push(item);
  }
  let incomplete = inventory.errors.length > 0;
  const queriedAdvisories = new Set<string>();
  const maximumAdvisories = 300;
  try {
    for (let offset = 0; offset < missing.length; offset += 100) {
      const batch = missing.slice(offset, offset + 100);
      const response = batchSchema.parse(
        await osvFetch(
          fetcher,
          'https://api.osv.dev/v1/querybatch',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({
              queries: batch.map((item) => ({
                package: { name: item.name, ecosystem: 'npm' },
                version: item.resolvedVersion,
              })),
            }),
          },
          signal,
        ),
      );
      if (response.results.length !== batch.length)
        throw new Error('OSV batch result count mismatch.');
      const candidateIds = [
        ...new Set(
          response.results.flatMap((result) => {
            if (result.next_page_token) incomplete = true;
            return (result.vulns ?? []).map((item) => item.id);
          }),
        ),
      ].filter((id) => !queriedAdvisories.has(id));
      const remaining = Math.max(0, maximumAdvisories - queriedAdvisories.size);
      if (candidateIds.length > remaining) incomplete = true;
      const ids = candidateIds.slice(0, remaining);
      const details = new Map<string, CompactRecord>();
      for (const id of ids) {
        if (!/^[A-Za-z0-9._:-]{1,100}$/.test(id)) {
          incomplete = true;
          continue;
        }
        queriedAdvisories.add(id);
        details.set(
          id,
          compact(
            await osvFetch(
              fetcher,
              `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
              { method: 'GET', headers: { Accept: 'application/json' } },
              signal,
            ),
          ),
        );
      }
      response.results.forEach((result, index) => {
        const item = batch[index];
        if (!item) return;
        const vulnerabilities = consolidate(
          (result.vulns ?? []).flatMap((entry) => {
            const detail = details.get(entry.id);
            return detail ? [detail] : [];
          }),
        );
        records.set(cacheKey(item), vulnerabilities);
        cache.entries[cacheKey(item)] = {
          fetchedAt: new Date(clock()).toISOString(),
          vulnerabilities,
        };
      });
    }
    if (missing.length) await saveCache(cachePath, cache);
  } catch (error) {
    return {
      dependencies: inventory.dependencies,
      findings: [],
      run: {
        id: 'osv',
        name: 'Dependency vulnerabilities',
        status: 'failed',
        durationMs: Date.now() - started,
        findings: 0,
        detail: `OSV lookup failed: ${redact(error instanceof Error ? error.message : 'unknown failure')}. No clean result is implied.`,
        version: 'API v1',
      },
    };
  }
  const findings: Finding[] = [];
  for (const item of resolved)
    for (const vulnerability of records.get(cacheKey(item)) ?? []) {
      if (findings.length >= 300) {
        incomplete = true;
        break;
      }
      findings.push(normalize(snapshot, item, vulnerability));
    }
  return {
    dependencies: inventory.dependencies,
    findings,
    run: {
      id: 'osv',
      name: 'Dependency vulnerabilities',
      status: incomplete ? 'partial' : 'completed',
      durationMs: Date.now() - started,
      findings: findings.length,
      detail: `Queried OSV for ${resolved.length} resolved npm ecosystem package(s). Only package names and versions left the machine; reachability was not assessed.${inventory.errors.length ? ' Some lockfiles were malformed.' : ''}`,
      version: 'API v1',
    },
  };
}
