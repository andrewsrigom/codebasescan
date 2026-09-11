import type { CoverageCapability, CoverageStatus, ScannerRun } from './types.ts';

function runStatus(run: ScannerRun, skipped: CoverageStatus): CoverageStatus {
  if (run.status === 'completed') return 'COMPLETE';
  if (run.status === 'partial') return 'PARTIAL';
  if (run.status === 'failed') return 'FAILED';
  if (run.status === 'skipped' && run.detail.startsWith('Disabled by audit mode selection.'))
    return 'DISABLED';
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

export function buildCoverage(runs: ScannerRun[]): CoverageCapability[] {
  return [
    scannerCapability(runs, 'project-profile', 'Project structure profile', 'NOT RUN'),
    scannerCapability(runs, 'ast-security', 'Framework-aware authorization', 'NOT RUN'),
    scannerCapability(runs, 'saas-security', 'SaaS application security', 'NOT RUN'),
    scannerCapability(runs, 'next-security', 'Next.js application security', 'NOT RUN'),
    scannerCapability(runs, 'react-security', 'React client security', 'NOT RUN'),
    scannerCapability(runs, 'accessibility-static', 'Static accessibility', 'NOT RUN'),
    scannerCapability(runs, 'axe-results', 'Imported Axe runtime accessibility', 'NOT PERFORMED'),
    scannerCapability(runs, 'web-posture', 'Web discovery and SEO posture', 'NOT RUN'),
    scannerCapability(runs, 'privacy-static', 'Static privacy', 'NOT RUN'),
    scannerCapability(runs, 'reliability-static', 'Static reliability', 'NOT RUN'),
    scannerCapability(runs, 'supply-chain', 'Node.js supply-chain integrity', 'NOT RUN'),
    scannerCapability(
      runs,
      'dependency-cruiser',
      'JavaScript/TypeScript dependency structure',
      'NOT SUPPORTED',
    ),
    scannerCapability(runs, 'jscpd', 'JavaScript/TypeScript code duplication', 'NOT SUPPORTED'),
    scannerCapability(runs, 'quality-metrics', 'Code quality metrics', 'NOT RUN'),
    scannerCapability(runs, 'knip', 'Dead code and dependency usage', 'NOT SUPPORTED'),
    scannerCapability(runs, 'builtin', 'Built-in static patterns', 'NOT RUN'),
    scannerCapability(runs, 'semgrep', 'Static code analysis', 'DISABLED'),
    scannerCapability(runs, 'gitleaks', 'Secret scanning', 'DISABLED'),
    scannerCapability(runs, 'osv', 'Dependency vulnerabilities', 'DISABLED'),
    scannerCapability(runs, 'posture', 'Security configuration', 'NOT RUN'),
    scannerCapability(runs, 'http-probe', 'HTTP runtime posture', 'NOT RUN'),
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
        'CodebaseScan does not exploit targets, brute-force authentication, or crawl applications.',
    },
  ];
}
