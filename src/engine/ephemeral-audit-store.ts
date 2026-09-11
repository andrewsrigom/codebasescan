import { randomUUID } from 'node:crypto';
import type {
  Audit,
  AuditOptions,
  AuditReport,
  AuditStatus,
  Finding,
  Project,
} from '../domain/types.ts';
import { parseAuditReport } from '../domain/report-schema.ts';
import { auditWorkflowVersion } from '../domain/versions.ts';
import { redact } from '../security/redact.ts';
import type { AuditExecutionStore } from './audit-store.ts';

const timestamp = () => new Date().toISOString();

export class EphemeralAuditStore implements AuditExecutionStore {
  private readonly projectsById = new Map<string, Project>();
  private readonly auditsById = new Map<string, Audit>();
  private readonly eventKeys = new Set<string>();

  close(): void {}

  registerProject(name: string, root: string): Project {
    const existing = [...this.projectsById.values()].find((project) => project.root === root);
    if (existing) return structuredClone(existing);
    const project = {
      id: randomUUID(),
      name: redact(name).slice(0, 100),
      root,
      createdAt: timestamp(),
    };
    this.projectsById.set(project.id, project);
    return structuredClone(project);
  }

  project(id: string): Project {
    const project = this.projectsById.get(id);
    if (!project) throw new Error('Project not found.');
    return structuredClone(project);
  }

  enqueue(projectId: string, options: AuditOptions = {}): Audit {
    const project = this.project(projectId);
    const createdAt = timestamp();
    const audit: Audit = {
      id: randomUUID(),
      workflowVersion: auditWorkflowVersion,
      projectId,
      projectName: project.name,
      status: 'queued',
      createdAt,
      updatedAt: createdAt,
      error: null,
      report: null,
      resumeNote: null,
      attempts: 0,
      options: structuredClone(options),
    };
    this.auditsById.set(audit.id, audit);
    this.event(audit.id, 'queued', 'queued', 'Audit queued for local execution.');
    return structuredClone(audit);
  }

  claim(id?: string): Audit | null {
    const audit = id
      ? this.auditsById.get(id)
      : [...this.auditsById.values()].find((candidate) => candidate.status === 'queued');
    if (!audit || audit.status !== 'queued') return null;
    audit.status = 'running';
    audit.attempts += 1;
    audit.updatedAt = timestamp();
    return structuredClone(audit);
  }

  audit(id: string): Audit {
    const audit = this.auditsById.get(id);
    if (!audit) throw new Error('Audit not found.');
    return structuredClone(audit);
  }

  saveProgress(id: string, report: AuditReport): void {
    const audit = this.auditsById.get(id);
    if (!audit || audit.status !== 'running') return;
    audit.report = parseAuditReport(structuredClone(report));
    audit.updatedAt = timestamp();
  }

  transition(id: string, status: AuditStatus, error: string | null = null): void {
    const audit = this.auditsById.get(id);
    if (!audit || audit.status === 'cancelled') return;
    audit.status = status;
    audit.error = error ? redact(error).slice(0, 400) : null;
    audit.updatedAt = timestamp();
  }

  event(auditId: string, key: string, stage: string, message: string): void {
    void stage;
    void message;
    this.eventKeys.add(`${auditId}:${key}`);
  }

  applySuppressions(_projectId: string, findings: Finding[]): Finding[] {
    return findings;
  }
}
