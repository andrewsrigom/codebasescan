import path from 'node:path';
import { access, mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import type { Configuration } from '../server/config.ts';
import { scannerCompatibility } from '../scanners/external.ts';
import type { TrustedScanner } from '../scanners/external.ts';
import { runScannerProcess } from '../security/process.ts';
import type { TrustedScannerBinary } from '../security/process.ts';

export type DoctorStatus = 'pass' | 'warn' | 'fail';

export interface DoctorCheck {
  name: string;
  status: DoctorStatus;
  detail: string;
}

interface AdvisorySummary {
  packages: number;
  latestFetch?: string;
}

export function supportedNodeVersion(version: string): boolean {
  const match = /^(?:v)?(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) return false;
  const [, majorText, minorText] = match;
  const major = Number(majorText);
  const minor = Number(minorText);
  return major > 22 || (major === 22 && minor >= 16);
}

export function summarizeAdvisoryDatabase(value: unknown): AdvisorySummary | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== 1 || !record.entries || typeof record.entries !== 'object')
    return null;
  const entries = Object.values(record.entries as Record<string, unknown>);
  const fetched = entries.flatMap((entry) => {
    if (!entry || typeof entry !== 'object') return [];
    const fetchedAt = (entry as Record<string, unknown>).fetchedAt;
    return typeof fetchedAt === 'string' && Number.isFinite(Date.parse(fetchedAt))
      ? [fetchedAt]
      : [];
  });
  return {
    packages: entries.length,
    ...(fetched.length ? { latestFetch: fetched.sort().at(-1) } : {}),
  };
}

async function dataDirectoryCheck(config: Configuration): Promise<DoctorCheck> {
  try {
    await mkdir(config.dataDirectory, { recursive: true, mode: 0o700 });
    await access(config.dataDirectory, constants.R_OK | constants.W_OK);
    const temporary = await mkdtemp(path.join(config.dataDirectory, 'doctor-'));
    await rm(temporary, { recursive: true, force: true });
    return { name: 'Data directory', status: 'pass', detail: config.dataDirectory };
  } catch {
    return {
      name: 'Data directory',
      status: 'fail',
      detail: `Cannot safely read and write ${config.dataDirectory}.`,
    };
  }
}

async function rulesDirectoryCheck(config: Configuration): Promise<DoctorCheck> {
  try {
    const metadata = await stat(config.rulesDirectory);
    if (!metadata.isDirectory()) throw new Error('Not a directory.');
    await access(config.rulesDirectory, constants.R_OK);
    return { name: 'Scanner rules', status: 'pass', detail: config.rulesDirectory };
  } catch {
    return {
      name: 'Scanner rules',
      status: 'fail',
      detail: `Rules directory is unavailable: ${config.rulesDirectory}.`,
    };
  }
}

async function scannerCheck(
  name: TrustedScanner,
  binary: TrustedScannerBinary,
  versionArguments: string[],
  enabled: boolean,
  config: Configuration,
): Promise<DoctorCheck> {
  try {
    const result = await runScannerProcess(binary, versionArguments, config.dataDirectory);
    const version = /\d+\.\d+\.\d+/.exec(result.stdout)?.[0];
    if (result.code !== 0 || !version) throw new Error('Version unavailable.');
    const compatibility = scannerCompatibility(name, version);
    return {
      name,
      status: compatibility.status === 'tested' ? 'pass' : 'warn',
      detail: `${version}; ${enabled ? 'enabled' : 'installed but disabled'}. ${compatibility.detail}`,
    };
  } catch {
    const bundled = binary === 'depcruise' || binary === 'jscpd';
    return {
      name,
      status: enabled ? 'fail' : 'warn',
      detail: enabled
        ? bundled
          ? 'Bundled scanner is unavailable.'
          : 'Enabled but unavailable on PATH.'
        : 'Optional binary not found; disabled.',
    };
  }
}

async function advisoryDatabaseCheck(config: Configuration): Promise<DoctorCheck> {
  try {
    const metadata = await stat(config.advisoryDatabasePath);
    if (!metadata.isFile() || metadata.size > 8 * 1024 * 1024)
      throw new Error('Invalid advisory database file.');
    const summary = summarizeAdvisoryDatabase(
      JSON.parse(await readFile(config.advisoryDatabasePath, 'utf8')) as unknown,
    );
    if (!summary) throw new Error('Invalid advisory database schema.');
    return {
      name: 'Advisory database',
      status: summary.packages ? 'pass' : 'warn',
      detail: `${summary.packages} exact package version(s) cached${summary.latestFetch ? `; latest refresh ${summary.latestFetch}` : ''}.`,
    };
  } catch {
    return {
      name: 'Advisory database',
      status: 'warn',
      detail: `No valid offline database at ${config.advisoryDatabasePath}. Run advisories update for a trusted project.`,
    };
  }
}

export async function runDoctor(config: Configuration): Promise<DoctorCheck[]> {
  const [dataDirectory, rulesDirectory, semgrep, gitleaks, dependencyCruiser, jscpd, advisories] =
    await Promise.all([
      dataDirectoryCheck(config),
      rulesDirectoryCheck(config),
      scannerCheck('semgrep', 'semgrep', ['--version'], config.semgrep, config),
      scannerCheck('gitleaks', 'gitleaks', ['version'], config.gitleaks, config),
      scannerCheck('dependency-cruiser', 'depcruise', ['--version'], true, config),
      scannerCheck('jscpd', 'jscpd', ['--version'], true, config),
      advisoryDatabaseCheck(config),
    ]);
  return [
    {
      name: 'Node.js',
      status: supportedNodeVersion(process.version) ? 'pass' : 'fail',
      detail: `${process.version}; Traceward requires >=22.16.0.`,
    },
    dataDirectory,
    rulesDirectory,
    semgrep,
    gitleaks,
    dependencyCruiser,
    jscpd,
    advisories,
    {
      name: 'AI mode',
      status: config.aiMode === 'openai' ? 'warn' : 'pass',
      detail:
        config.aiMode === 'disabled'
          ? 'disabled; audits make no model calls.'
          : config.aiMode === 'ollama'
            ? `local Ollama model configured: ${config.model}.`
            : `OpenAI cloud mode enabled with model ${config.model}; API key is configured but not displayed.`,
    },
  ];
}

export function renderDoctor(checks: DoctorCheck[]): string {
  const label: Record<DoctorStatus, string> = { pass: 'PASS', warn: 'WARN', fail: 'FAIL' };
  return checks
    .map((check) => `${label[check.status].padEnd(4)}  ${check.name}: ${check.detail}`)
    .join('\n');
}
