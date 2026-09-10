import { createServer, type Server } from 'node:http';
import path from 'node:path';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { z } from 'zod';
import { digest } from '../domain/findings.ts';
import { parseAuditReport } from '../domain/report-schema.ts';
import { parseRunManifest } from '../domain/run-manifest-schema.ts';
import type { AuditReport } from '../domain/types.ts';
import type { RunManifest } from '../domain/run-manifest.ts';
import { staticReportVersion, type StaticReportManifest } from './static-report.ts';

const manifestLimitBytes = 1024 * 1024;
const artifactLimitBytes = 64 * 1024 * 1024;
const packageLimitBytes = 256 * 1024 * 1024;
const candidateLimit = 1_000;

const artifactPath = z
  .string()
  .min(1)
  .max(1_000)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/);

const manifestSchema = z.object({
  schemaVersion: z.literal(staticReportVersion),
  kind: z.literal('traceward-static-report'),
  auditId: z.string().min(1).max(100),
  snapshotDigest: z.string().regex(/^[a-f0-9]{64}$/),
  generatedAt: z.iso.datetime(),
  entrypoint: z.literal('index.html'),
  files: z
    .array(
      z.object({
        path: artifactPath,
        mediaType: z
          .string()
          .min(1)
          .max(200)
          .regex(/^[^\u0000-\u001f\u007f]+$/),
        bytes: z.number().int().nonnegative().max(artifactLimitBytes),
        sha256: z.string().regex(/^[a-f0-9]{64}$/),
      }),
    )
    .min(3)
    .max(1_000),
});

export interface LoadedReportPackage {
  directory: string;
  manifest: StaticReportManifest;
  report: AuditReport;
  runManifest: RunManifest;
  files: ReadonlyMap<string, StaticReportManifest['files'][number]>;
}

export interface ReportServer {
  server: Server;
  url: string;
  reportPackage: LoadedReportPackage;
  close(): Promise<void>;
}

async function readBoundedFile(file: string, limit: number): Promise<Buffer> {
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > limit)
    throw new Error(`Report artifact is not a regular file within the size limit: ${file}`);
  return readFile(file);
}

function containedArtifact(directory: string, relativePath: string): string {
  const resolved = path.resolve(directory, relativePath);
  const relative = path.relative(directory, resolved);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative))
    throw new Error(`Report manifest contains an unsafe artifact path: ${relativePath}`);
  return resolved;
}

async function readManifest(directory: string): Promise<StaticReportManifest> {
  const value = await readBoundedFile(path.join(directory, 'manifest.json'), manifestLimitBytes);
  try {
    return manifestSchema.parse(JSON.parse(value.toString('utf8'))) as StaticReportManifest;
  } catch {
    throw new Error(`Static report manifest is invalid: ${path.join(directory, 'manifest.json')}`);
  }
}

async function packageDirectory(location: string): Promise<string> {
  const resolved = path.resolve(location);
  const metadata = await lstat(resolved);
  const directory = metadata.isDirectory() ? resolved : path.dirname(resolved);

  try {
    await lstat(path.join(directory, 'manifest.json'));
    return directory;
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
  }

  const entries = (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && /^[A-Za-z0-9-]{1,100}$/.test(entry.name))
    .slice(0, candidateLimit);
  const candidates = await Promise.all(
    entries.map(async (entry) => {
      const candidate = path.join(directory, entry.name);
      try {
        return { directory: candidate, manifest: await readManifest(candidate) };
      } catch {
        return null;
      }
    }),
  );
  const latest = candidates
    .filter((candidate): candidate is NonNullable<typeof candidate> => candidate !== null)
    .sort((left, right) => right.manifest.generatedAt.localeCompare(left.manifest.generatedAt))[0];
  if (!latest) throw new Error(`No valid Traceward report package was found at ${directory}.`);
  return latest.directory;
}

function requireArtifacts(files: ReadonlyMap<string, StaticReportManifest['files'][number]>): void {
  for (const required of ['index.html', 'audit-report.json', 'run-manifest.json'])
    if (!files.has(required)) throw new Error(`Static report is missing ${required}.`);
}

export async function loadReportPackage(location: string): Promise<LoadedReportPackage> {
  const directory = await packageDirectory(location);
  const manifest = await readManifest(directory);
  const files = new Map<string, StaticReportManifest['files'][number]>();
  const dataArtifacts = new Map<string, Buffer>();
  let packageBytes = 0;

  for (const artifact of manifest.files) {
    if (files.has(artifact.path))
      throw new Error(`Static report declares duplicate artifact ${artifact.path}.`);
    files.set(artifact.path, artifact);
    packageBytes += artifact.bytes;
    if (packageBytes > packageLimitBytes)
      throw new Error('Static report exceeds the package limit.');
    const content = await readBoundedFile(
      containedArtifact(directory, artifact.path),
      artifactLimitBytes,
    );
    if (
      content.byteLength !== artifact.bytes ||
      digest(content.toString('utf8')) !== artifact.sha256
    )
      throw new Error(`Static report artifact failed integrity validation: ${artifact.path}`);
    if (artifact.path === 'audit-report.json' || artifact.path === 'run-manifest.json')
      dataArtifacts.set(artifact.path, content);
  }
  requireArtifacts(files);

  let report: AuditReport;
  let runManifest: RunManifest;
  try {
    report = parseAuditReport(JSON.parse(dataArtifacts.get('audit-report.json')!.toString('utf8')));
    runManifest = parseRunManifest(
      JSON.parse(dataArtifacts.get('run-manifest.json')!.toString('utf8')),
    );
  } catch {
    throw new Error('Static report contains invalid Traceward data.');
  }

  if (
    manifest.auditId !== report.auditId ||
    manifest.auditId !== runManifest.audit.id ||
    manifest.snapshotDigest !== report.snapshotDigest ||
    manifest.snapshotDigest !== runManifest.audit.snapshotDigest ||
    manifest.generatedAt !== report.createdAt ||
    runManifest.audit.createdAt !== report.createdAt ||
    runManifest.audit.projectName !== report.projectName ||
    runManifest.audit.reportSchemaVersion !== report.schemaVersion
  )
    throw new Error('Static report identity does not match its audit artifacts.');

  for (const output of runManifest.outputs) {
    const artifact = files.get(output.path);
    if (
      !artifact ||
      artifact.bytes !== output.bytes ||
      artifact.sha256 !== output.sha256 ||
      artifact.mediaType !== output.mediaType
    )
      throw new Error(`Run manifest does not match static artifact ${output.path}.`);
  }

  return { directory, manifest, report, runManifest, files };
}

async function verifiedArtifact(
  reportPackage: LoadedReportPackage,
  artifact: StaticReportManifest['files'][number],
): Promise<Buffer> {
  const content = await readBoundedFile(
    containedArtifact(reportPackage.directory, artifact.path),
    artifactLimitBytes,
  );
  if (content.byteLength !== artifact.bytes || digest(content.toString('utf8')) !== artifact.sha256)
    throw new Error(`Report artifact changed after validation: ${artifact.path}`);
  return content;
}

function requestedArtifact(url: string | undefined): string | null {
  try {
    const pathname = new URL(url ?? '/', 'http://127.0.0.1').pathname;
    return pathname === '/' ? 'index.html' : decodeURIComponent(pathname.slice(1));
  } catch {
    return null;
  }
}

export async function startReportServer(location: string, port = 4173): Promise<ReportServer> {
  if (!Number.isInteger(port) || port < 0 || port > 65_535)
    throw new Error('Report server port must be an integer from 0 to 65535.');
  const reportPackage = await loadReportPackage(location);
  const server = createServer(async (request, response) => {
    response.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
    response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Cache-Control', 'no-store');

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.writeHead(405, { Allow: 'GET, HEAD' }).end('Method not allowed.');
      return;
    }
    const requested = requestedArtifact(request.url);
    const artifact = requested ? reportPackage.files.get(requested) : undefined;
    if (!artifact) {
      response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found.');
      return;
    }
    try {
      const content = await verifiedArtifact(reportPackage, artifact);
      response.writeHead(200, {
        'Content-Type': artifact.mediaType,
        'Content-Length': content.byteLength,
      });
      response.end(request.method === 'HEAD' ? undefined : content);
    } catch {
      response
        .writeHead(409, { 'Content-Type': 'text/plain; charset=utf-8' })
        .end('Report artifact changed. Restart Traceward after restoring the report package.');
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    server.close();
    throw new Error('Traceward could not determine the report server address.');
  }
  return {
    server,
    url: `http://127.0.0.1:${address.port}/`,
    reportPackage,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
