import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import type {
  Audit,
  AuditOptions,
  AuditEvent,
  AuditReport,
  AuditStatus,
  ControlReviewDecision,
  Finding,
  Project,
  ReviewDecision,
  SuppressionDecision,
} from '../domain/types.ts';
import { redact } from '../security/redact.ts';
import { parseAuditReport, parseStoredAuditOptions } from '../domain/report-schema.ts';
import { auditWorkflowVersion } from '../domain/versions.ts';
type Row = Record<string, unknown>;
const now = () => new Date().toISOString();
function storedJson(value: string, label: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new Error(`Stored ${label} is malformed JSON.`);
  }
}
function readAudit(row: Row): Audit {
  return {
    id: String(row.id),
    workflowVersion: String(row.workflow_version ?? auditWorkflowVersion),
    projectId: String(row.project_id),
    projectName: String(row.project_name),
    status: row.status as AuditStatus,
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    error: typeof row.error === 'string' ? row.error : null,
    report:
      typeof row.report_json === 'string'
        ? parseAuditReport(storedJson(row.report_json, 'audit report'))
        : null,
    resumeNote: typeof row.resume_note === 'string' ? row.resume_note : null,
    attempts: Number(row.attempts),
    options:
      typeof row.options_json === 'string'
        ? parseStoredAuditOptions(storedJson(row.options_json, 'audit options'))
        : {},
  };
}
export class AuditStore {
  readonly db: DatabaseSync;
  constructor(databasePath: string) {
    if (databasePath !== ':memory:')
      mkdirSync(path.dirname(databasePath), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(databasePath);
    if (databasePath !== ':memory:') chmodSync(databasePath, 0o600);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, root TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
        baseline_audit_id TEXT
      );
      CREATE TABLE IF NOT EXISTS audits (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
        project_name TEXT NOT NULL, status TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        error TEXT, report_json TEXT, resume_note TEXT, attempts INTEGER NOT NULL DEFAULT 0,
        options_json TEXT NOT NULL DEFAULT '{}',
        workflow_version TEXT NOT NULL DEFAULT '${auditWorkflowVersion}'
      );
      CREATE UNIQUE INDEX IF NOT EXISTS one_active_audit ON audits(project_id)
        WHERE status IN ('queued', 'running', 'awaiting_review');
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id TEXT NOT NULL REFERENCES audits(id),
        event_key TEXT NOT NULL, stage TEXT NOT NULL, message TEXT NOT NULL, at TEXT NOT NULL,
        UNIQUE(audit_id, event_key)
      );
      CREATE TABLE IF NOT EXISTS worker_lock (
        name TEXT PRIMARY KEY, token TEXT NOT NULL, pid INTEGER NOT NULL, heartbeat TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS report_revisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_id TEXT NOT NULL REFERENCES audits(id),
        source TEXT NOT NULL,
        report_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS report_revisions_audit
        ON report_revisions(audit_id, id);
      CREATE TABLE IF NOT EXISTS project_suppressions (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES projects(id),
        fingerprint TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        UNIQUE(project_id, fingerprint)
      );
      CREATE INDEX IF NOT EXISTS project_suppressions_project
        ON project_suppressions(project_id, expires_at);
    `);
    const auditColumns = this.db.prepare('PRAGMA table_info(audits)').all() as Row[];
    if (!auditColumns.some((column) => column.name === 'options_json'))
      this.db.exec("ALTER TABLE audits ADD COLUMN options_json TEXT NOT NULL DEFAULT '{}'");
    if (!auditColumns.some((column) => column.name === 'workflow_version'))
      this.db.exec(
        "ALTER TABLE audits ADD COLUMN workflow_version TEXT NOT NULL DEFAULT 'codebasescan-audit-v1'",
      );
    const projectColumns = this.db.prepare('PRAGMA table_info(projects)').all() as Row[];
    if (!projectColumns.some((column) => column.name === 'baseline_audit_id'))
      this.db.exec('ALTER TABLE projects ADD COLUMN baseline_audit_id TEXT');
    this.db.exec('PRAGMA user_version = 5;');
  }
  close(): void {
    this.db.close();
  }
  registerProject(name: string, root: string): Project {
    const existing = this.db.prepare('SELECT * FROM projects WHERE root = ?').get(root) as
      Row | undefined;
    if (existing) return this.project(String(existing.id));
    const project = { id: randomUUID(), name: redact(name).slice(0, 100), root, createdAt: now() };
    this.db
      .prepare('INSERT INTO projects(id, name, root, created_at) VALUES (?, ?, ?, ?)')
      .run(project.id, project.name, root, project.createdAt);
    return project;
  }
  project(id: string): Project {
    const row = this.db.prepare('SELECT * FROM projects WHERE id = ?').get(id) as Row | undefined;
    if (!row) throw new Error('Project not found. Register it through the local CLI.');
    return {
      id: String(row.id),
      name: String(row.name),
      root: String(row.root),
      createdAt: String(row.created_at),
      ...(typeof row.baseline_audit_id === 'string'
        ? { baselineAuditId: row.baseline_audit_id }
        : {}),
    };
  }
  projects(): Project[] {
    return (this.db.prepare('SELECT id FROM projects ORDER BY created_at DESC').all() as Row[]).map(
      (row) => this.project(String(row.id)),
    );
  }
  setProjectBaseline(projectId: string, auditId: string): void {
    const audit = this.audit(auditId);
    if (audit.projectId !== projectId || audit.status !== 'completed' || !audit.report)
      throw new Error('A baseline must be a completed report from the same project.');
    this.db
      .prepare('UPDATE projects SET baseline_audit_id = ? WHERE id = ?')
      .run(auditId, projectId);
  }
  projectBaseline(projectId: string): Audit | null {
    const baseline = this.project(projectId).baselineAuditId;
    if (!baseline) return null;
    try {
      const audit = this.audit(baseline);
      return audit.projectId === projectId && audit.report ? audit : null;
    } catch {
      return null;
    }
  }
  enqueue(projectId: string, options: AuditOptions = {}): Audit {
    const project = this.project(projectId);
    const id = randomUUID();
    try {
      this.db
        .prepare(
          'INSERT INTO audits(id, project_id, project_name, status, created_at, updated_at, options_json, workflow_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        )
        .run(
          id,
          project.id,
          project.name,
          'queued',
          now(),
          now(),
          JSON.stringify(options),
          auditWorkflowVersion,
        );
    } catch (error) {
      if (error instanceof Error && error.message.includes('UNIQUE'))
        throw new Error('This project already has an active audit. Finish or cancel it first.');
      throw error;
    }
    this.event(id, 'queued', 'queued', 'Audit queued for the local worker.');
    return this.audit(id);
  }
  audit(id: string): Audit {
    const row = this.db.prepare('SELECT * FROM audits WHERE id = ?').get(id) as Row | undefined;
    if (!row) throw new Error('Audit not found.');
    return readAudit(row);
  }
  audits(): Audit[] {
    return (
      this.db.prepare('SELECT * FROM audits ORDER BY created_at DESC LIMIT 100').all() as Row[]
    ).map(readAudit);
  }
  claim(id?: string): Audit | null {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = (
        id
          ? this.db.prepare("SELECT * FROM audits WHERE status = 'queued' AND id = ?").get(id)
          : this.db
              .prepare("SELECT * FROM audits WHERE status = 'queued' ORDER BY created_at LIMIT 1")
              .get()
      ) as Row | undefined;
      if (!row) {
        this.db.exec('COMMIT');
        return null;
      }
      this.db
        .prepare(
          "UPDATE audits SET status = 'running', updated_at = ?, attempts = attempts + 1 WHERE id = ?",
        )
        .run(now(), String(row.id));
      this.db.exec('COMMIT');
      return this.audit(String(row.id));
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  saveProgress(id: string, report: AuditReport): void {
    const serialized = JSON.stringify(parseAuditReport(report));
    const timestamp = now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = this.db
        .prepare(
          "UPDATE audits SET report_json = ?, updated_at = ? WHERE id = ? AND status = 'running'",
        )
        .run(serialized, timestamp, id);
      if (result.changes)
        this.db
          .prepare(
            'INSERT INTO report_revisions(audit_id, source, report_json, created_at) VALUES (?, ?, ?, ?)',
          )
          .run(id, 'workflow', serialized, timestamp);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  transition(id: string, status: AuditStatus, error: string | null = null): void {
    this.db
      .prepare(
        "UPDATE audits SET status = ?, error = ?, updated_at = ? WHERE id = ? AND status != 'cancelled'",
      )
      .run(status, error ? redact(error).slice(0, 400) : null, now(), id);
  }
  publish(id: string, note: string): void {
    const result = this.db
      .prepare(
        "UPDATE audits SET status = 'queued', resume_note = ?, updated_at = ? WHERE id = ? AND status = 'awaiting_review'",
      )
      .run(redact(note), now(), id);
    if (!result.changes) throw new Error('This audit is not waiting for publication review.');
    this.event(
      id,
      'review-submitted',
      'human_review',
      'Publication review submitted. Unresolved findings retain their status.',
    );
  }
  reviewFinding(id: string, decision: ReviewDecision): void {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const audit = this.audit(id);
      if (!['awaiting_review', 'completed'].includes(audit.status) || !audit.report)
        throw new Error('Findings can be reviewed only after analysis has paused or finished.');
      const finding = audit.report.findings.find((item) => item.id === decision.findingId);
      if (!finding) throw new Error('Finding not found.');
      finding.disposition = decision.disposition;
      finding.review = { decision: decision.disposition, note: redact(decision.note), at: now() };
      const serialized = JSON.stringify(parseAuditReport(audit.report));
      const timestamp = now();
      this.db
        .prepare('UPDATE audits SET report_json = ?, updated_at = ? WHERE id = ?')
        .run(serialized, timestamp, id);
      this.db
        .prepare(
          'INSERT INTO report_revisions(audit_id, source, report_json, created_at) VALUES (?, ?, ?, ?)',
        )
        .run(id, 'human-review', serialized, timestamp);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    this.event(
      id,
      `review:${decision.findingId}:${randomUUID()}`,
      'human_review',
      `An analyst changed finding ${decision.findingId} to ${decision.disposition}.`,
    );
  }
  applySuppressions(projectId: string, findings: Finding[]): Finding[] {
    const timestamp = now();
    const rows = this.db
      .prepare(
        'SELECT fingerprint, reason, created_at, expires_at FROM project_suppressions WHERE project_id = ? AND (expires_at IS NULL OR expires_at > ?)',
      )
      .all(projectId, timestamp) as Row[];
    const suppressions = new Map(rows.map((row) => [String(row.fingerprint), row]));
    return findings.map((finding) => {
      const suppression = suppressions.get(finding.fingerprint);
      if (!suppression) return finding;
      return {
        ...finding,
        suppression: {
          reason: String(suppression.reason),
          createdAt: String(suppression.created_at),
          ...(typeof suppression.expires_at === 'string'
            ? { expiresAt: suppression.expires_at }
            : {}),
        },
      };
    });
  }
  suppressFinding(id: string, decision: SuppressionDecision): void {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const audit = this.audit(id);
      if (!['awaiting_review', 'completed'].includes(audit.status) || !audit.report)
        throw new Error('Exceptions can be created only after analysis has paused or finished.');
      const finding = audit.report.findings.find((item) => item.id === decision.findingId);
      if (!finding) throw new Error('Finding not found.');
      const createdAt = now();
      this.db
        .prepare(
          `INSERT INTO project_suppressions(id, project_id, fingerprint, reason, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(project_id, fingerprint) DO UPDATE SET
             reason = excluded.reason, created_at = excluded.created_at, expires_at = excluded.expires_at`,
        )
        .run(
          randomUUID(),
          audit.projectId,
          finding.fingerprint,
          redact(decision.reason),
          createdAt,
          decision.expiresAt ?? null,
        );
      finding.suppression = {
        reason: redact(decision.reason),
        createdAt,
        ...(decision.expiresAt ? { expiresAt: decision.expiresAt } : {}),
      };
      this.saveHumanReport(id, audit.report, 'suppression');
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    this.event(
      id,
      `suppression:${decision.findingId}:${randomUUID()}`,
      'human_review',
      `An analyst created a project exception for finding ${decision.findingId}.`,
    );
  }
  removeSuppression(id: string, findingId: string): void {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const audit = this.audit(id);
      if (!audit.report) throw new Error('No report is available.');
      const finding = audit.report.findings.find((item) => item.id === findingId);
      if (!finding) throw new Error('Finding not found.');
      this.db
        .prepare('DELETE FROM project_suppressions WHERE project_id = ? AND fingerprint = ?')
        .run(audit.projectId, finding.fingerprint);
      delete finding.suppression;
      this.saveHumanReport(id, audit.report, 'suppression-removed');
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  private saveHumanReport(id: string, report: AuditReport, source: string): void {
    const serialized = JSON.stringify(parseAuditReport(report));
    const timestamp = now();
    this.db
      .prepare('UPDATE audits SET report_json = ?, updated_at = ? WHERE id = ?')
      .run(serialized, timestamp, id);
    this.db
      .prepare(
        'INSERT INTO report_revisions(audit_id, source, report_json, created_at) VALUES (?, ?, ?, ?)',
      )
      .run(id, source, serialized, timestamp);
  }
  reviewControl(id: string, decision: ControlReviewDecision): void {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const audit = this.audit(id);
      if (!['awaiting_review', 'completed'].includes(audit.status) || !audit.report?.checklist)
        throw new Error('Controls can be reviewed only after a checklist is available.');
      const control = audit.report.checklist.controls.find(
        (item) => item.id === decision.controlId,
      );
      if (!control) throw new Error('Control not found.');
      control.review = { decision: decision.decision, note: redact(decision.note), at: now() };
      const serialized = JSON.stringify(parseAuditReport(audit.report));
      const timestamp = now();
      this.db
        .prepare('UPDATE audits SET report_json = ?, updated_at = ? WHERE id = ?')
        .run(serialized, timestamp, id);
      this.db
        .prepare(
          'INSERT INTO report_revisions(audit_id, source, report_json, created_at) VALUES (?, ?, ?, ?)',
        )
        .run(id, 'human-review', serialized, timestamp);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    this.event(
      id,
      `control-review:${decision.controlId}:${randomUUID()}`,
      'human_review',
      `An analyst assessed control ${decision.controlId} as ${decision.decision}.`,
    );
  }
  cancel(id: string): void {
    const result = this.db
      .prepare(
        "UPDATE audits SET status = 'cancelled', updated_at = ? WHERE id = ? AND status IN ('queued', 'running', 'awaiting_review')",
      )
      .run(now(), id);
    if (!result.changes) throw new Error('Only active audits can be cancelled.');
    this.event(
      id,
      'cancelled',
      'cancelled',
      'Audit cancelled. Existing evidence remains available.',
    );
  }
  event(auditId: string, key: string, stage: string, message: string): void {
    this.db
      .prepare(
        'INSERT OR IGNORE INTO events(audit_id, event_key, stage, message, at) VALUES (?, ?, ?, ?, ?)',
      )
      .run(auditId, key, stage, redact(message).slice(0, 500), now());
  }
  events(auditId: string): AuditEvent[] {
    return (
      this.db
        .prepare('SELECT * FROM events WHERE audit_id = ? ORDER BY id LIMIT 1000')
        .all(auditId) as Row[]
    ).map((row) => ({
      id: Number(row.id),
      auditId,
      stage: String(row.stage),
      message: String(row.message),
      at: String(row.at),
    }));
  }
  reportRevisions(auditId: string): {
    id: number;
    source: string;
    createdAt: string;
    report: AuditReport;
  }[] {
    return (
      this.db
        .prepare(
          'SELECT id, source, report_json, created_at FROM report_revisions WHERE audit_id = ? ORDER BY id',
        )
        .all(auditId) as Row[]
    ).map((row) => ({
      id: Number(row.id),
      source: String(row.source),
      createdAt: String(row.created_at),
      report: parseAuditReport(storedJson(String(row.report_json), 'report revision')),
    }));
  }
  acquireWorker(): string {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare("SELECT * FROM worker_lock WHERE name = 'local'").get() as
        Row | undefined;
      if (existing) {
        let live = true;
        try {
          process.kill(Number(existing.pid), 0);
        } catch (error) {
          live = (error as NodeJS.ErrnoException).code !== 'ESRCH';
        }
        if (live)
          throw new Error(
            'A local worker is already running. Stop it before starting another worker.',
          );
        this.db.exec("DELETE FROM worker_lock WHERE name = 'local'");
      }
      const token = randomUUID();
      this.db
        .prepare("INSERT INTO worker_lock VALUES ('local', ?, ?, ?)")
        .run(token, process.pid, now());
      this.db
        .prepare(
          "UPDATE audits SET status = CASE WHEN attempts >= 3 THEN 'failed' ELSE 'queued' END, error = 'Previous worker stopped; recovery requested.', updated_at = ? WHERE status = 'running'",
        )
        .run(now());
      this.db.exec('COMMIT');
      return token;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  heartbeat(token: string): void {
    this.db
      .prepare("UPDATE worker_lock SET heartbeat = ? WHERE name = 'local' AND token = ?")
      .run(now(), token);
  }
  releaseWorker(token: string): void {
    this.db.prepare("DELETE FROM worker_lock WHERE name = 'local' AND token = ?").run(token);
  }
  workerOnline(): boolean {
    const row = this.db.prepare("SELECT heartbeat FROM worker_lock WHERE name = 'local'").get() as
      Row | undefined;
    return Boolean(row && Date.now() - Date.parse(String(row.heartbeat)) < 10000);
  }
}
