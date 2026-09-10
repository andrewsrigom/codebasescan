import { auditModePackVersion } from './audit-modes.ts';
import type {
  AuditMode,
  AuditModeSelection,
  AuditReport,
  CoverageCapability,
  CoverageStatus,
  ScannerRun,
  ScannerStatus,
} from './types.ts';
import { auditWorkflowVersion, codebasescanVersion } from './versions.ts';

export const runManifestVersion = 2 as const;

export interface RunManifestOutput {
  path: string;
  mediaType: string;
  bytes: number;
  sha256: string;
}

export interface RunManifest {
  schemaVersion: typeof runManifestVersion;
  kind: 'codebasescan-audit-run';
  codebasescanVersion: string;
  workflowVersion: string;
  packVersion: string;
  audit: {
    id: string;
    projectName: string;
    createdAt: string;
    snapshotDigest: string;
    reportSchemaVersion: AuditReport['schemaVersion'];
    aiMode: AuditReport['aiMode'];
    publication: AuditReport['publication'];
  };
  modes: {
    selectionAvailable: boolean;
    requested: AuditMode[];
    effective: AuditModeSelection[];
  };
  scope: {
    filesAnalyzed: number;
    skipped: Record<string, number>;
    truncated: boolean;
    preflight: AuditReport['scopePreflight'] | null;
  };
  execution: {
    scannerDurationMs: number;
    scannerStatus: Record<ScannerStatus, number>;
    cache: {
      eligible: number;
      hits: number;
      misses: number;
    };
    scanners: ScannerRun[];
  };
  coverage: {
    status: Record<CoverageStatus, number>;
    capabilities: CoverageCapability[];
  };
  limitations: string[];
  outputs: RunManifestOutput[];
}

const emptyScannerStatus = (): Record<ScannerStatus, number> => ({
  completed: 0,
  partial: 0,
  skipped: 0,
  failed: 0,
});

const emptyCoverageStatus = (): Record<CoverageStatus, number> => ({
  COMPLETE: 0,
  PARTIAL: 0,
  FAILED: 0,
  'NOT RUN': 0,
  DISABLED: 0,
  'NOT SUPPORTED': 0,
  'NOT PERFORMED': 0,
});

export function buildRunManifest(report: AuditReport, outputs: RunManifestOutput[]): RunManifest {
  const scannerStatus = emptyScannerStatus();
  for (const scanner of report.scanners) scannerStatus[scanner.status] += 1;
  const cachedScanners = report.scanners.filter((scanner) => scanner.cache);

  const capabilities = report.coverage ?? [];
  const coverageStatus = emptyCoverageStatus();
  for (const capability of capabilities) coverageStatus[capability.status] += 1;

  const effective = report.auditModes ?? [];
  return {
    schemaVersion: runManifestVersion,
    kind: 'codebasescan-audit-run',
    codebasescanVersion,
    workflowVersion: auditWorkflowVersion,
    packVersion: auditModePackVersion,
    audit: {
      id: report.auditId,
      projectName: report.projectName,
      createdAt: report.createdAt,
      snapshotDigest: report.snapshotDigest,
      reportSchemaVersion: report.schemaVersion,
      aiMode: report.aiMode,
      publication: report.publication,
    },
    modes: {
      selectionAvailable: report.auditModes !== undefined,
      requested: effective.filter((mode) => mode.enabled).map((mode) => mode.id),
      effective: structuredClone(effective),
    },
    scope: {
      filesAnalyzed: report.filesAnalyzed,
      skipped: { ...report.skipped },
      truncated: report.truncated,
      preflight: report.scopePreflight ? structuredClone(report.scopePreflight) : null,
    },
    execution: {
      scannerDurationMs: report.scanners.reduce((total, scanner) => total + scanner.durationMs, 0),
      scannerStatus,
      cache: {
        eligible: cachedScanners.length,
        hits: cachedScanners.filter((scanner) => scanner.cache?.status === 'hit').length,
        misses: cachedScanners.filter((scanner) => scanner.cache?.status === 'miss').length,
      },
      scanners: structuredClone(report.scanners),
    },
    coverage: {
      status: coverageStatus,
      capabilities: structuredClone(capabilities),
    },
    limitations: [...report.limitations],
    outputs: structuredClone(outputs),
  };
}
