import path from 'node:path';
import { mkdtemp, mkdir, writeFile, rm, stat, readFile } from 'node:fs/promises';
import type { Finding, ScannerRun, Snapshot } from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import { record } from '../domain/validation.ts';
import { safeRelative } from '../security/paths.ts';
import { redact } from '../security/redact.ts';
import { runScannerProcess } from '../security/process.ts';
export interface ScanResult {
  findings: Finding[];
  run: ScannerRun;
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
export function normalizeSemgrep(
  value: unknown,
  snapshot: Snapshot,
  stagingRoot?: string,
): Finding[] {
  const envelope = record(value);
  if (!Array.isArray(envelope.results)) throw new Error('Unsupported Semgrep JSON schema.');
  const findings: Finding[] = [];
  for (const raw of envelope.results.slice(0, 300)) {
    const item = record(raw);
    const file = locate(snapshot, item.path, stagingRoot);
    if (!file) continue;
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
  }
  return findings;
}
export function normalizeGitleaks(
  value: unknown,
  snapshot: Snapshot,
  stagingRoot?: string,
): Finding[] {
  if (!Array.isArray(value)) throw new Error('Unsupported Gitleaks JSON schema.');
  const findings: Finding[] = [];
  for (const raw of value.slice(0, 300)) {
    const item = record(raw);
    const file = locate(snapshot, item.File, stagingRoot);
    if (!file) continue;
    const line = item.StartLine;
    if (
      typeof line !== 'number' ||
      !Number.isSafeInteger(line) ||
      line < 1 ||
      line > file.content.split('\n').length
    )
      continue;
    const evidence = sourceEvidence(
      file,
      line,
      'A secret-shaped value matched a Gitleaks rule. Activity and validity are not checked.',
    );
    evidence.excerpt = '[Source excerpt withheld for secret findings]';
    findings.push(
      makeFinding({
        source: 'gitleaks',
        ruleId: safeString(item.RuleID, 'gitleaks.unknown'),
        title: safeString(item.Description, 'Potential hardcoded credential'),
        severity: 'high',
        sourceSeverity: 'UNSPECIFIED',
        category: 'secrets',
        cwe: ['CWE-798'],
        description:
          'A credential pattern was detected. The raw match and secret value are intentionally discarded, not stored or sent to a model.',
        remediation:
          'Determine whether the value is real. If exposure is confirmed, rotate it and remove it from source and relevant history.',
        evidence: [evidence],
      }),
    );
  }
  return findings;
}
export async function scanExternal(
  name: 'semgrep' | 'gitleaks',
  snapshot: Snapshot,
  enabled: boolean,
  temporaryDirectory: string,
  rulesDirectory: string,
  signal?: AbortSignal,
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
    await mkdir(sourceRoot, { mode: 0o700 });
    for (const file of snapshot.files) {
      const destination = path.join(sourceRoot, safeRelative(file.path));
      await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
      await writeFile(destination, file.content, { mode: 0o600, flag: 'wx' });
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
            '--json',
            '--quiet',
            sourceRoot,
          ]
        : [
            'dir',
            sourceRoot,
            '--no-banner',
            '--ignore-gitleaks-allow',
            '--redact=100',
            '--config',
            path.join(rulesDirectory, 'gitleaks.toml'),
            '--report-format=json',
            `--report-path=${reportPath}`,
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
        : normalizeGitleaks(parsed, snapshot, sourceRoot);
    const envelope = name === 'semgrep' ? record(parsed) : null;
    const errors = envelope && Array.isArray(envelope.errors) ? envelope.errors.length : 0;
    const rawCount =
      name === 'semgrep' && Array.isArray(envelope?.results)
        ? envelope.results.length
        : Array.isArray(parsed)
          ? parsed.length
          : 0;
    if (result.code === 1 && rawCount === 0)
      throw new Error('Scanner signaled findings but supplied no valid report entries.');
    const partial =
      findings.length >= 300 || errors > 0 || snapshot.truncated || rawCount !== findings.length;
    return {
      findings,
      run: {
        id: name,
        name,
        status: partial ? 'partial' : 'completed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: findings.length,
        detail: `${name} analyzed the bounded staging snapshot with trusted local configuration.${errors ? ' Some files could not be analyzed.' : ''}`,
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
