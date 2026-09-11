import type { Finding, ScannerRun } from './types.ts';

const scannerBySource: Record<Finding['source'], string> = {
  builtin: 'builtin',
  posture: 'posture',
  ast: 'ast-security',
  saas: 'saas-security',
  next: 'next-security',
  react: 'react-security',
  accessibility: 'accessibility-static',
  axe: 'axe-results',
  web: 'web-posture',
  privacy: 'privacy-static',
  reliability: 'reliability-static',
  environment: 'environment-contract',
  'supply-chain': 'supply-chain',
  'http-probe': 'http-probe',
  osv: 'osv',
  semgrep: 'semgrep',
  gitleaks: 'gitleaks',
};

const detectorBySource: Record<Finding['source'], NonNullable<Finding['provenance']>['detector']> =
  {
    builtin: 'codebasescan-heuristic',
    posture: 'codebasescan-heuristic',
    ast: 'codebasescan-ast',
    saas: 'codebasescan-ast',
    next: 'codebasescan-ast',
    react: 'codebasescan-ast',
    accessibility: 'codebasescan-ast',
    axe: 'runtime-probe',
    web: 'codebasescan-ast',
    privacy: 'codebasescan-ast',
    reliability: 'codebasescan-ast',
    environment: 'codebasescan-ast',
    'supply-chain': 'codebasescan-heuristic',
    'http-probe': 'runtime-probe',
    osv: 'advisory-database',
    semgrep: 'scanner',
    gitleaks: 'scanner',
  };

export function attachProvenance(
  findings: Finding[],
  scanners: ScannerRun[],
  detectedAt: string,
): Finding[] {
  return findings.map((finding) => {
    const scannerId = scannerBySource[finding.source];
    const scanner = scanners.find((item) => item.id === scannerId);
    return {
      ...finding,
      provenance: {
        detector: detectorBySource[finding.source],
        scanner: scanner?.name ?? scannerId,
        ruleId: finding.ruleId,
        ...(scanner?.version ? { scannerVersion: scanner.version } : {}),
        originalSeverity: finding.sourceSeverity,
        detectedAt,
        evidenceKinds: [
          ...new Set(finding.evidence.map((item) => item.kind ?? ('source' as const))),
        ],
      },
    };
  });
}
