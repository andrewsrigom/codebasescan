import type { Audit, AuditReport, AuditStatus, Finding, Project } from '../domain/types.ts';

export interface AuditExecutionStore {
  audit(id: string): Audit;
  project(id: string): Project;
  saveProgress(id: string, report: AuditReport): void;
  transition(id: string, status: AuditStatus, error?: string | null): void;
  event(auditId: string, key: string, stage: string, message: string): void;
  applySuppressions(projectId: string, findings: Finding[]): Finding[];
}
