import path from 'node:path';
import { mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import type {
  ArchitectureAnalysis,
  ArchitectureCycle,
  ArchitectureHotspot,
  DuplicateBlock,
  DuplicateLocation,
  DuplicationAnalysis,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';
import { digest } from '../domain/findings.ts';
import { record } from '../domain/validation.ts';
import { isRuntimeSource, safeRelative } from '../security/paths.ts';
import { runScannerProcess } from '../security/process.ts';
import { scannerCompatibility } from './external.ts';
import { writeSnapshotStage } from './staging.ts';

const maximumReportBytes = 8 * 1024 * 1024;
const maximumCycles = 100;
const maximumOrphans = 200;
const maximumHotspots = 100;
const maximumDuplicateBlocks = 100;
const sourceExtension = /\.[cm]?[jt]sx?$/i;

export interface ArchitectureScanResult {
  analysis?: ArchitectureAnalysis;
  run: ScannerRun;
}

export interface DuplicationScanResult {
  analysis?: DuplicationAnalysis;
  run: ScannerRun;
}

function boundedInteger(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? Math.min(value, maximum)
    : 0;
}

function boundedNumber(value: unknown, minimum: number, maximum: number): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.min(maximum, Math.max(minimum, value))
    : minimum;
}

function sourceFiles(snapshot: Snapshot): SourceFile[] {
  return snapshot.files.filter(isSupportedSource);
}

function isSupportedSource(file: SourceFile): boolean {
  return isRuntimeSource(file) && sourceExtension.test(file.path) && !file.path.endsWith('.d.ts');
}

function locateSource(snapshot: Snapshot, reportedPath: unknown, stagingRoot?: string) {
  if (typeof reportedPath !== 'string') return undefined;
  try {
    const relative =
      stagingRoot && path.isAbsolute(reportedPath)
        ? path.relative(stagingRoot, reportedPath)
        : reportedPath.replace(/^\.\//, '');
    const normalized = safeRelative(relative);
    return snapshot.files.find(
      (file) =>
        file.path === normalized && isRuntimeSource(file) && sourceExtension.test(file.path),
    );
  } catch {
    return undefined;
  }
}

function canonicalCycle(files: string[]): string[] {
  const seen = new Set<string>();
  const normalized = files.filter((file) => {
    if (seen.has(file)) return false;
    seen.add(file);
    return true;
  });
  if (normalized.length < 2) return [];
  const rotations = normalized.map((_, index) => [
    ...normalized.slice(index),
    ...normalized.slice(0, index),
  ]);
  rotations.sort((left, right) => left.join('\0').localeCompare(right.join('\0')));
  return rotations[0] ?? [];
}

function isExpectedRoot(file: string, profile?: ProjectProfile): boolean {
  if (profile?.entrypoints.some((entrypoint) => entrypoint.file === file)) return true;
  return /(?:^|\/)(?:page|layout|loading|error|global-error|not-found|default|template|middleware|proxy|instrumentation|next\.config)\.[cm]?[jt]sx?$/.test(
    file,
  );
}

export function normalizeArchitecture(
  value: unknown,
  snapshot: Snapshot,
  profile?: ProjectProfile,
  stagingRoot?: string,
): ArchitectureAnalysis {
  const envelope = record(value);
  if (!Array.isArray(envelope.modules))
    throw new Error('Unsupported dependency-cruiser JSON schema.');

  const modules = envelope.modules.flatMap((raw) => {
    const item = record(raw);
    const source = locateSource(snapshot, item.source, stagingRoot);
    if (!source || !Array.isArray(item.dependencies)) return [];
    const dependencies = item.dependencies.flatMap((rawDependency) => {
      const dependency = record(rawDependency);
      const target = locateSource(snapshot, dependency.resolved, stagingRoot);
      return target ? [{ raw: dependency, file: target.path }] : [];
    });
    const dependents = Array.isArray(item.dependents)
      ? item.dependents.flatMap((candidate) => {
          const dependent = locateSource(snapshot, candidate, stagingRoot);
          return dependent ? [dependent.path] : [];
        })
      : [];
    const incoming = new Set(dependents).size;
    const outgoing = new Set(dependencies.map((dependency) => dependency.file)).size;
    const reportedInstability = boundedNumber(item.instability, 0, 1);
    const instability =
      typeof item.instability === 'number'
        ? reportedInstability
        : incoming + outgoing
          ? outgoing / (incoming + outgoing)
          : 0;
    return [
      {
        file: source.path,
        dependencies,
        incoming,
        outgoing,
        instability,
        orphan: item.orphan === true,
      },
    ];
  });

  const cycles = new Map<string, ArchitectureCycle>();
  for (const sourceModule of modules)
    for (const dependency of sourceModule.dependencies) {
      if (dependency.raw.circular !== true) continue;
      const reportedCycle = Array.isArray(dependency.raw.cycle)
        ? dependency.raw.cycle.flatMap((rawStep) => {
            const step = record(rawStep);
            const file = locateSource(snapshot, step.name, stagingRoot);
            return file ? [file.path] : [];
          })
        : [];
      const files = canonicalCycle([sourceModule.file, ...reportedCycle, dependency.file]);
      if (files.length < 2) continue;
      const id = digest(`architecture-cycle:${files.join('>')}`).slice(0, 16);
      cycles.set(id, { id, files });
    }

  const orphanCandidates = modules
    .filter((sourceModule) => sourceModule.orphan && !isExpectedRoot(sourceModule.file, profile))
    .map((sourceModule) => sourceModule.file)
    .sort();
  const hotspots: ArchitectureHotspot[] = modules
    .filter((sourceModule) => sourceModule.incoming + sourceModule.outgoing > 0)
    .map((sourceModule) => ({
      file: sourceModule.file,
      incoming: sourceModule.incoming,
      outgoing: sourceModule.outgoing,
      instability: Number(sourceModule.instability.toFixed(4)),
    }))
    .sort(
      (left, right) =>
        right.incoming + right.outgoing - (left.incoming + left.outgoing) ||
        left.file.localeCompare(right.file),
    );
  return {
    schemaVersion: 1,
    modules: modules.length,
    localDependencies: modules.reduce((total, sourceModule) => total + sourceModule.outgoing, 0),
    cycles: [...cycles.values()].slice(0, maximumCycles),
    orphanCandidates: orphanCandidates.slice(0, maximumOrphans),
    hotspots: hotspots.slice(0, maximumHotspots),
    truncated:
      snapshot.truncated ||
      cycles.size > maximumCycles ||
      orphanCandidates.length > maximumOrphans ||
      hotspots.length > maximumHotspots,
  };
}

function duplicateLocation(
  value: unknown,
  snapshot: Snapshot,
  stagingRoot?: string,
): DuplicateLocation | undefined {
  const item = record(value);
  const file = locateSource(snapshot, item.name, stagingRoot);
  const startLine = boundedInteger(item.start);
  const endLine = boundedInteger(item.end);
  const fileLines = file?.content.split('\n').length ?? 0;
  if (!file || startLine < 1 || endLine < startLine || endLine > fileLines) return undefined;
  return { file: file.path, startLine, endLine };
}

export function normalizeDuplication(
  value: unknown,
  snapshot: Snapshot,
  stagingRoot?: string,
): DuplicationAnalysis {
  const envelope = record(value);
  if (
    !envelope.statistics ||
    typeof envelope.statistics !== 'object' ||
    Array.isArray(envelope.statistics) ||
    !Array.isArray(envelope.duplicates)
  )
    throw new Error('Unsupported jscpd JSON schema.');
  const statistics = record(envelope.statistics);
  if (!statistics.total || typeof statistics.total !== 'object' || Array.isArray(statistics.total))
    throw new Error('Unsupported jscpd JSON schema.');
  const total = record(statistics.total);
  if (Object.keys(total).length === 0) throw new Error('Unsupported jscpd JSON schema.');

  const blocks = new Map<string, DuplicateBlock>();
  for (const raw of envelope.duplicates) {
    const item = record(raw);
    const first = duplicateLocation(item.firstFile, snapshot, stagingRoot);
    const second = duplicateLocation(item.secondFile, snapshot, stagingRoot);
    const lines = boundedInteger(item.lines, 10_000);
    const tokens = boundedInteger(item.tokens, 1_000_000);
    if (!first || !second || !lines || !tokens) continue;
    const ordered = [first, second].sort((left, right) =>
      `${left.file}:${left.startLine}`.localeCompare(`${right.file}:${right.startLine}`),
    );
    const id = digest(
      `duplicate:${ordered.map((location) => `${location.file}:${location.startLine}:${location.endLine}`).join('|')}`,
    ).slice(0, 16);
    blocks.set(id, {
      id,
      kind: item.kind === 'similar' ? 'similar' : 'exact',
      format: typeof item.format === 'string' ? item.format.slice(0, 80) : 'unknown',
      lines,
      tokens,
      first: ordered[0]!,
      second: ordered[1]!,
    });
  }
  const normalized = [...blocks.values()].sort(
    (left, right) => right.lines - left.lines || left.id.localeCompare(right.id),
  );
  const clones = boundedInteger(total.clones, 1_000_000);
  return {
    schemaVersion: 1,
    files: boundedInteger(total.sources, 1_000_000),
    lines: boundedInteger(total.lines, 100_000_000),
    tokens: boundedInteger(total.tokens, 1_000_000_000),
    clones,
    duplicatedLines: boundedInteger(total.duplicatedLines, 100_000_000),
    percentage: Number(boundedNumber(total.percentage, 0, 100).toFixed(4)),
    blocks: normalized.slice(0, maximumDuplicateBlocks),
    truncated:
      snapshot.truncated ||
      normalized.length > maximumDuplicateBlocks ||
      clones !== normalized.length,
  };
}

async function readBoundedReport(reportPath: string): Promise<unknown> {
  const metadata = await stat(reportPath);
  if (!metadata.isFile() || metadata.size > maximumReportBytes)
    throw new Error('Mechanical scanner report exceeded the 8 MB limit.');
  return JSON.parse(await readFile(reportPath, 'utf8')) as unknown;
}

async function scannerVersion(
  binary: 'depcruise' | 'jscpd',
  cwd: string,
  signal?: AbortSignal,
): Promise<string | undefined> {
  try {
    const result = await runScannerProcess(binary, ['--version'], cwd, signal);
    return result.code === 0 ? /\d+\.\d+\.\d+/.exec(result.stdout)?.[0] : undefined;
  } catch {
    return undefined;
  }
}

export async function scanArchitecture(
  snapshot: Snapshot,
  profile: ProjectProfile | undefined,
  temporaryDirectory: string,
  signal?: AbortSignal,
): Promise<ArchitectureScanResult> {
  const started = performance.now();
  if (!sourceFiles(snapshot).length)
    return {
      run: {
        id: 'dependency-cruiser',
        name: 'Dependency structure',
        status: 'skipped',
        durationMs: 0,
        findings: 0,
        detail: 'No supported runtime JavaScript or TypeScript source was captured.',
      },
    };
  await mkdir(temporaryDirectory, { recursive: true, mode: 0o700 });
  const stage = await mkdtemp(path.join(temporaryDirectory, 'dependency-cruiser-'));
  const sourceRoot = path.join(stage, 'source');
  const reportPath = path.join(stage, 'result.json');
  try {
    await writeSnapshotStage(snapshot, sourceRoot, isSupportedSource);
    const version = await scannerVersion('depcruise', sourceRoot, signal);
    const result = await runScannerProcess(
      'depcruise',
      [
        '--no-config',
        '--output-type',
        'json',
        '--metrics',
        '--progress',
        'none',
        '--output-to',
        reportPath,
        '.',
      ],
      sourceRoot,
      signal,
    );
    if (result.code !== 0) throw new Error('dependency-cruiser returned an error.');
    const analysis = normalizeArchitecture(
      await readBoundedReport(reportPath),
      snapshot,
      profile,
      sourceRoot,
    );
    const compatibility = scannerCompatibility('dependency-cruiser', version);
    const partial = analysis.truncated || compatibility.status !== 'tested';
    return {
      analysis,
      run: {
        id: 'dependency-cruiser',
        name: 'Dependency structure',
        status: partial ? 'partial' : 'completed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: `${analysis.modules} modules and ${analysis.localDependencies} local dependencies were mapped; ${analysis.cycles.length} cycle(s) and ${analysis.orphanCandidates.length} orphan candidate(s) are mechanical review data, not vulnerabilities. Target configuration was not loaded. ${compatibility.detail}`,
        ...(version ? { version } : {}),
      },
    };
  } catch {
    return {
      run: {
        id: 'dependency-cruiser',
        name: 'Dependency structure',
        status: 'failed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail:
          'Dependency structure analysis did not complete. No clean architecture result is implied.',
      },
    };
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

export async function scanDuplication(
  snapshot: Snapshot,
  temporaryDirectory: string,
  signal?: AbortSignal,
): Promise<DuplicationScanResult> {
  const started = performance.now();
  if (!sourceFiles(snapshot).length)
    return {
      run: {
        id: 'jscpd',
        name: 'Code duplication',
        status: 'skipped',
        durationMs: 0,
        findings: 0,
        detail: 'No supported runtime JavaScript or TypeScript source was captured.',
      },
    };
  await mkdir(temporaryDirectory, { recursive: true, mode: 0o700 });
  const stage = await mkdtemp(path.join(temporaryDirectory, 'jscpd-'));
  const sourceRoot = path.join(stage, 'source');
  const outputDirectory = path.join(stage, 'report');
  const reportPath = path.join(outputDirectory, 'jscpd-report.json');
  try {
    await writeSnapshotStage(snapshot, sourceRoot, isSupportedSource);
    await mkdir(outputDirectory, { mode: 0o700 });
    const version = await scannerVersion('jscpd', sourceRoot, signal);
    const result = await runScannerProcess(
      'jscpd',
      [
        '--reporters',
        'json',
        '--output',
        outputDirectory,
        '--silent',
        '--no-colors',
        '--no-gitignore',
        '--min-lines',
        '10',
        '--min-tokens',
        '70',
        '--max-lines',
        '200',
        '--max-size',
        '256kb',
        '--format',
        'javascript,jsx,typescript,tsx',
        '--ignore',
        '**/*.d.ts,**/*.min.js,**/*.generated.*,**/node_modules/**',
        '--workers',
        '2',
        '.',
      ],
      sourceRoot,
      signal,
    );
    if (result.code !== 0) throw new Error('jscpd returned an error.');
    const analysis = normalizeDuplication(
      await readBoundedReport(reportPath),
      snapshot,
      sourceRoot,
    );
    const compatibility = scannerCompatibility('jscpd', version);
    const partial = analysis.truncated || compatibility.status !== 'tested';
    return {
      analysis,
      run: {
        id: 'jscpd',
        name: 'Code duplication',
        status: partial ? 'partial' : 'completed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: `${analysis.clones} clone(s), ${analysis.duplicatedLines} duplicated line(s), and ${analysis.percentage}% duplication were measured. Source fragments were discarded. Duplicates are maintainability evidence, not vulnerabilities. ${compatibility.detail}`,
        ...(version ? { version } : {}),
      },
    };
  } catch {
    return {
      run: {
        id: 'jscpd',
        name: 'Code duplication',
        status: 'failed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: 'Code duplication analysis did not complete. No clean result is implied.',
      },
    };
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}
