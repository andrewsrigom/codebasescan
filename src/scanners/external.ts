import path from 'node:path';
import {
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  unlink,
} from 'node:fs/promises';
import type { Finding, ScannerRun, Snapshot } from '../domain/types.ts';
import { digest, makeFinding, sourceEvidence } from '../domain/findings.ts';
import { record } from '../domain/validation.ts';
import { isRuntimeSource, safeRelative } from '../security/paths.ts';
import { redact } from '../security/redact.ts';
import { runScannerProcess } from '../security/process.ts';
import { writeSnapshotStage } from './staging.ts';
export interface ScanResult {
  findings: Finding[];
  run: ScannerRun;
}
type ExternalScanner = 'semgrep' | 'gitleaks';
export type TrustedScanner = ExternalScanner | 'dependency-cruiser' | 'jscpd';
export interface ExternalScanOptions {
  projectRoot?: string;
  gitHistory?: boolean;
}
export const testedScannerVersions: Record<TrustedScanner, readonly string[]> = {
  semgrep: ['1.176.1'],
  gitleaks: ['8.30.1'],
  'dependency-cruiser': ['18.2.0'],
  jscpd: ['5.2.0'],
};
export function scannerCompatibility(name: TrustedScanner, version?: string) {
  const tested = testedScannerVersions[name];
  if (!version)
    return {
      status: 'unknown' as const,
      detail: `Compatibility warning: the ${name} version could not be identified. Parsed output is retained, but coverage is partial.`,
    };
  if (tested.includes(version))
    return {
      status: 'tested' as const,
      detail: `${name} ${version} is covered by the Traceward scanner compatibility fixtures.`,
    };
  return {
    status: 'untested' as const,
    detail: `Compatibility warning: ${name} ${version} is outside the tested version set (${tested.join(', ')}). Parsed output is retained, but coverage is partial.`,
  };
}
const stagingName = /^(?:semgrep|gitleaks|dependency-cruiser|jscpd)-[A-Za-z0-9._-]+$/;
export async function cleanupStaleScannerStaging(temporaryDirectory: string): Promise<number> {
  await mkdir(temporaryDirectory, { recursive: true, mode: 0o700 });
  const root = path.resolve(temporaryDirectory);
  let removed = 0;
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!stagingName.test(entry.name)) continue;
    const candidate = path.resolve(root, entry.name);
    if (path.dirname(candidate) !== root) continue;
    const metadata = await lstat(candidate);
    if (metadata.isSymbolicLink()) await unlink(candidate);
    else if (metadata.isDirectory()) await rm(candidate, { recursive: true, force: true });
    else continue;
    removed++;
  }
  return removed;
}
function safeString(input: unknown, fallback: string): string {
  return typeof input === 'string' ? redact(input).slice(0, 2000) : fallback;
}
function locate(snapshot: Snapshot, scannerPath: unknown, stagingRoot?: string) {
  if (typeof scannerPath !== 'string') return undefined;
  try {
    const relative =
      stagingRoot && path.isAbsolute(scannerPath)
        ? path.relative(stagingRoot, scannerPath)
        : scannerPath.replace(/^\.\//, '');
    const normalized = safeRelative(relative);
    return snapshot.files.find((file) => file.path === normalized);
  } catch {
    return undefined;
  }
}

function historyEvidence(item: Record<string, unknown>, projectRoot?: string) {
  if (typeof item.File !== 'string') return null;
  try {
    const relative = safeRelative(
      projectRoot && path.isAbsolute(item.File) ? path.relative(projectRoot, item.File) : item.File,
    );
    const line =
      typeof item.StartLine === 'number' &&
      Number.isSafeInteger(item.StartLine) &&
      item.StartLine > 0
        ? item.StartLine
        : 1;
    const commit =
      typeof item.Commit === 'string' && /^[a-f0-9]{7,64}$/i.test(item.Commit)
        ? item.Commit.toLowerCase()
        : undefined;
    const observation = commit
      ? `A secret-shaped value matched in Git commit ${commit.slice(0, 12)}. The raw value and matched line were discarded.`
      : 'A secret-shaped value matched in Git history. The raw value and matched line were discarded.';
    return {
      evidence: {
        id: makeHistoryEvidenceId(relative, line, commit),
        kind: 'history' as const,
        file: relative,
        startLine: line,
        endLine: line,
        excerpt: '[Historical source excerpt withheld for secret findings]',
        fileDigest: makeHistoryEvidenceId(relative, 0, commit),
        observation,
      },
      commit,
    };
  } catch {
    return null;
  }
}

function makeHistoryEvidenceId(file: string, line: number, commit?: string): string {
  return digest(`git-history:${commit ?? 'unknown'}:${file}:${line}`).slice(0, 16);
}
export function normalizeSemgrep(
  value: unknown,
  snapshot: Snapshot,
  stagingRoot?: string,
): Finding[] {
  const envelope = record(value);
  if (!Array.isArray(envelope.results)) throw new Error('Unsupported Semgrep JSON schema.');
  const findings: Finding[] = [];
  for (const raw of envelope.results) {
    const item = record(raw);
    const file = locate(snapshot, item.path, stagingRoot);
    if (!file || !isRuntimeSource(file)) continue;
    const start = record(item.start);
    const extra = record(item.extra);
    const line = start.line;
    if (
      typeof line !== 'number' ||
      !Number.isSafeInteger(line) ||
      line < 1 ||
      line > file.content.split('\n').length
    )
      continue;
    const severity =
      extra.severity === 'ERROR' ? 'high' : extra.severity === 'WARNING' ? 'medium' : 'info';
    const ruleId = safeString(item.check_id, 'semgrep.unknown');
    findings.push(
      makeFinding({
        source: 'semgrep',
        ruleId,
        title: safeString(extra.message, 'Static analysis finding'),
        severity,
        sourceSeverity: safeString(extra.severity, 'UNKNOWN'),
        category: 'code',
        description:
          'Semgrep matched a rule against this snapshot. Source severity is preserved; exploitability still requires contextual review.',
        remediation:
          'Inspect the complete data flow and verify a fix with a focused regression test.',
        cwe: [],
        evidence: [sourceEvidence(file, line, `Semgrep rule: ${ruleId}`)],
      }),
    );
    if (findings.length >= 300) break;
  }
  return findings;
}
export function normalizeGitleaks(
  value: unknown,
  snapshot: Snapshot,
  stagingRoot?: string,
  history = false,
): Finding[] {
  if (!Array.isArray(value)) throw new Error('Unsupported Gitleaks JSON schema.');
  const findings: Finding[] = [];
  for (const raw of value.slice(0, 300)) {
    const item = record(raw);
    const file = locate(snapshot, item.File, stagingRoot);
    const historical = history ? historyEvidence(item, stagingRoot) : null;
    if (history && !historical) continue;
    if (!file && !history) continue;
    const line = item.StartLine;
    if (!history) {
      if (
        typeof line !== 'number' ||
        !Number.isSafeInteger(line) ||
        line < 1 ||
        line > file!.content.split('\n').length
      )
        continue;
    }
    const evidence = history
      ? historical!.evidence
      : sourceEvidence(
          file!,
          line as number,
          'A secret-shaped value matched a Gitleaks rule. Activity and validity are not checked.',
        );
    if (!history) evidence.excerpt = '[Source excerpt withheld for secret findings]';
    const fixtureCandidate = !history && file!.scope !== 'runtime';
    findings.push(
      makeFinding({
        source: 'gitleaks',
        ruleId: safeString(item.RuleID, 'gitleaks.unknown'),
        title: safeString(item.Description, 'Potential hardcoded credential'),
        severity: fixtureCandidate ? 'medium' : 'high',
        sourceSeverity: 'UNSPECIFIED',
        category: 'secrets',
        cwe: ['CWE-798'],
        description: history
          ? 'A credential pattern was detected in Git history. The raw match and secret value are intentionally discarded, not stored or sent to a model.'
          : fixtureCandidate
            ? 'A credential pattern was detected in test or example source. It is classified as a fixture candidate until a reviewer establishes whether it is active. The raw value is discarded.'
            : 'A credential pattern was detected in runtime source. It is classified as probable until validity is reviewed. The raw match and secret value are intentionally discarded, not stored or sent to a model.',
        remediation:
          'Determine whether the value is real. If exposure is confirmed, rotate it and remove it from source and relevant history.',
        evidence: [evidence],
        confidence: fixtureCandidate ? 'low' : 'medium',
        secret: {
          classification: history
            ? 'historical'
            : fixtureCandidate
              ? 'fixture_candidate'
              : 'probable',
          ...(historical?.commit ? { commit: historical.commit } : {}),
        },
      }),
    );
  }
  return findings;
}
export async function scanExternal(
  name: ExternalScanner,
  snapshot: Snapshot,
  enabled: boolean,
  temporaryDirectory: string,
  rulesDirectory: string,
  signal?: AbortSignal,
  options: ExternalScanOptions = {},
): Promise<ScanResult> {
  const started = performance.now();
  if (!enabled)
    return {
      findings: [],
      run: {
        id: name,
        name,
        status: 'skipped',
        durationMs: 0,
        findings: 0,
        detail: 'Disabled. Install the binary and opt in through local configuration.',
      },
    };
  await mkdir(temporaryDirectory, { recursive: true, mode: 0o700 });
  const stage = await mkdtemp(path.join(temporaryDirectory, `${name}-`));
  const sourceRoot = path.join(stage, 'source');
  const reportPath = path.join(stage, 'result.json');
  try {
    const history = name === 'gitleaks' && options.gitHistory === true;
    const projectRoot = options.projectRoot ? path.resolve(options.projectRoot) : undefined;
    if (history && !projectRoot)
      throw new Error('Git history scanning requires the validated project root.');
    if (history) {
      const gitMetadata = await stat(path.join(projectRoot!, '.git'));
      if (!gitMetadata.isDirectory() && !gitMetadata.isFile())
        throw new Error('The project does not contain Git metadata.');
    }
    let version: string | undefined;
    try {
      const versionResult = await runScannerProcess(
        name,
        name === 'semgrep' ? ['--version'] : ['version'],
        stage,
        signal,
      );
      const match = /\d+\.\d+\.\d+/.exec(versionResult.stdout);
      if (versionResult.code === 0 && match) version = match[0];
    } catch {
      /* A scan can still be useful when version discovery alone fails. */
    }
    if (!history) {
      await writeSnapshotStage(snapshot, sourceRoot);
    }
    const args =
      name === 'semgrep'
        ? [
            'scan',
            '--config',
            path.join(rulesDirectory, 'semgrep.yml'),
            '--metrics=off',
            '--disable-version-check',
            '--disable-nosem',
            '--no-git-ignore',
            '--timeout',
            '15',
            '--json',
            '--quiet',
            sourceRoot,
          ]
        : [
            history ? 'git' : 'dir',
            ...(history ? ['--log-opts=--all'] : [sourceRoot]),
            '--no-banner',
            '--ignore-gitleaks-allow',
            '--redact=100',
            '--config',
            path.join(rulesDirectory, 'gitleaks.toml'),
            '--report-format=json',
            `--report-path=${reportPath}`,
            ...(history ? [projectRoot!] : []),
          ];
    const result = await runScannerProcess(name, args, stage, signal);
    if (result.code !== 0 && !(name === 'gitleaks' && result.code === 1))
      throw new Error(`${name} returned a scanner error, not a clean scan.`);
    let payload = result.stdout;
    if (name === 'gitleaks') {
      const reportMetadata = await stat(reportPath);
      if (reportMetadata.size > 4 * 1024 * 1024)
        throw new Error('Scanner report exceeded the 4 MB limit.');
      payload = await readFile(reportPath, 'utf8');
    }
    const parsed: unknown = JSON.parse(payload);
    const findings =
      name === 'semgrep'
        ? normalizeSemgrep(parsed, snapshot, sourceRoot)
        : normalizeGitleaks(parsed, snapshot, history ? projectRoot : sourceRoot, history);
    const envelope = name === 'semgrep' ? record(parsed) : null;
    const errors = envelope && Array.isArray(envelope.errors) ? envelope.errors.length : 0;
    const rawCount =
      name === 'semgrep' && Array.isArray(envelope?.results)
        ? envelope.results.length
        : Array.isArray(parsed)
          ? parsed.length
          : 0;
    const applicableRawCount =
      name === 'semgrep' && Array.isArray(envelope?.results)
        ? envelope.results.filter((raw) => {
            const item = record(raw);
            const file = locate(snapshot, item.path, sourceRoot);
            return Boolean(file && isRuntimeSource(file));
          }).length
        : rawCount;
    const compatibility = scannerCompatibility(name, version);
    if (result.code === 1 && rawCount === 0)
      throw new Error('Scanner signaled findings but supplied no valid report entries.');
    const partial =
      findings.length >= 300 ||
      errors > 0 ||
      snapshot.truncated ||
      applicableRawCount !== findings.length ||
      compatibility.status !== 'tested';
    return {
      findings,
      run: {
        id: name,
        name,
        status: partial ? 'partial' : 'completed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: findings.length,
        detail: `${name} analyzed ${history ? 'the explicitly approved Git history' : 'the bounded staging snapshot'} with trusted local configuration. Raw secret values were discarded.${errors ? ' Some files could not be analyzed.' : ''} ${compatibility.detail}`,
        ...(version ? { version } : {}),
      },
    };
  } catch {
    const detail =
      'Scanner did not complete. Check binary availability, schema compatibility, timeout and output limits. No clean result is implied.';
    return {
      findings: [],
      run: {
        id: name,
        name,
        status: 'failed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail,
      },
    };
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}
