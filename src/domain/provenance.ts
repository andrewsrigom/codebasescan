import type { Finding, ScannerRun } from './types.ts';

const scannerBySource: Record<Finding['source'], string> = {
  builtin: 'builtin',
  posture: 'posture',
  ast: 'ast-security',
  'http-probe': 'http-probe',
  osv: 'osv',
  semgrep: 'semgrep',
  gitleaks: 'gitleaks',
};

const detectorBySource: Record<Finding['source'], NonNullable<Finding['provenance']>['detector']> =
  {
    builtin: 'traceward-heuristic',
    posture: 'traceward-heuristic',
    ast: 'traceward-ast',
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
