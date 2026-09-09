import type {
  AuditReport,
  CoverageCapability,
  CoverageStatus,
  Finding,
  ScannerRun,
} from './types.ts';

function runStatus(run: ScannerRun, skipped: CoverageStatus): CoverageStatus {
  if (run.status === 'completed') return 'COMPLETE';
  if (run.status === 'partial') return 'PARTIAL';
  if (run.status === 'failed') return 'FAILED';
  return skipped;
}

function scannerCapability(
  runs: ScannerRun[],
  id: string,
  label: string,
  skipped: CoverageStatus,
): CoverageCapability {
  const run = runs.find((item) => item.id === id);
  if (!run)
    return {
      id,
      label,
      status: 'NOT RUN',
      detail: 'No scanner run was recorded for this capability.',
    };
  return {
    id,
    label,
    status: runStatus(run, skipped),
    detail: run.detail,
    findings: run.findings,
    ...(run.version ? { version: run.version } : {}),
  };
}

function aiCapability(aiMode: AuditReport['aiMode'], findings: Finding[]): CoverageCapability {
  if (aiMode === 'disabled')
    return {
      id: 'ai-context',
      label: 'AI contextual analysis',
      status: 'DISABLED',
      detail: 'Model inference was disabled. Deterministic findings remain available.',
    };
  const modelAnalyses = findings.filter((item) => item.analysis?.kind === aiMode);
  const inconclusive = modelAnalyses.filter((item) => item.analysis?.assessment === 'inconclusive');
  return {
    id: 'ai-context',
    label: 'AI contextual analysis',
    status: modelAnalyses.length === 0 ? 'FAILED' : inconclusive.length ? 'PARTIAL' : 'COMPLETE',
    detail: `${modelAnalyses.length} finding(s) received ${aiMode} analysis; ${inconclusive.length} were inconclusive. Model analysis never suppresses scanner evidence.`,
  };
}

export function buildCoverage(
  runs: ScannerRun[],
  findings: Finding[],
  aiMode: AuditReport['aiMode'],
): CoverageCapability[] {
  return [
    scannerCapability(runs, 'project-profile', 'Project structure profile', 'NOT RUN'),
    scannerCapability(runs, 'ast-security', 'Framework-aware authorization', 'NOT RUN'),
    scannerCapability(runs, 'builtin', 'Built-in static patterns', 'NOT RUN'),
    scannerCapability(runs, 'semgrep', 'Static code analysis', 'DISABLED'),
    scannerCapability(runs, 'gitleaks', 'Secret scanning', 'DISABLED'),
    scannerCapability(runs, 'osv', 'Dependency vulnerabilities', 'DISABLED'),
    scannerCapability(runs, 'posture', 'Security configuration', 'NOT RUN'),
    scannerCapability(runs, 'http-probe', 'HTTP runtime posture', 'NOT RUN'),
    aiCapability(aiMode, findings),
    {
      id: 'infrastructure-as-code',
      label: 'Infrastructure as Code',
      status: 'NOT SUPPORTED',
      detail:
        'No dedicated Terraform, CloudFormation, or equivalent policy scanner is implemented.',
    },
    {
      id: 'cloud-iam',
      label: 'Cloud IAM',
      status: 'NOT SUPPORTED',
      detail: 'Cloud account and effective IAM policy analysis are outside this release.',
    },
    {
      id: 'dynamic-exploitation',
      label: 'Dynamic exploitation',
      status: 'NOT PERFORMED',
      detail:
        'Traceward does not exploit targets, brute-force authentication, or crawl applications.',
    },
  ];
}
