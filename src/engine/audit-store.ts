import type { Audit, AuditReport, AuditStatus, Finding, Project } from '../domain/types.ts';

export interface AuditExecutionStore {
  audit(id: string): Audit;
  project(id: string): Project;
  saveProgress(id: string, report: AuditReport): void;
  transition(id: string, status: AuditStatus, error?: string | null): void;
  event(auditId: string, key: string, stage: string, message: string): void;
  applySuppressions(projectId: string, findings: Finding[]): Finding[];
  reserveAiCall(
    auditId: string,
    estimatedInputTokens: number,
    limits: { calls: number; inputTokens: number; outputTokens: number; outputPerCall: number },
  ): { maximumOutputTokens: number };
  finalizeAiCall(
    auditId: string,
    estimatedInputTokens: number,
    actual: { inputTokens: number; outputTokens: number; approximateCostUsd: number },
  ): void;
  recordAiCacheHit(auditId: string): void;
  aiUsage(auditId: string): {
    calls: number;
    cacheHits: number;
    inputTokens: number;
    outputTokens: number;
    approximateCostUsd: number;
  };
  readAiCache<T>(key: string, maximumAgeMs: number): T | null;
  saveAiCache(key: string, value: unknown): void;
}
