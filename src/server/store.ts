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
  Project,
  ReviewDecision,
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
        id TEXT PRIMARY KEY, name TEXT NOT NULL, root TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audits (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
        project_name TEXT NOT NULL, status TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        error TEXT, report_json TEXT, resume_note TEXT, attempts INTEGER NOT NULL DEFAULT 0,
        options_json TEXT NOT NULL DEFAULT '{}',
        workflow_version TEXT NOT NULL DEFAULT 'traceward-audit-v1'
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
      CREATE TABLE IF NOT EXISTS ai_usage (
        audit_id TEXT PRIMARY KEY REFERENCES audits(id), calls INTEGER NOT NULL DEFAULT 0,
        cache_hits INTEGER NOT NULL DEFAULT 0, input_tokens INTEGER NOT NULL DEFAULT 0,
        output_tokens INTEGER NOT NULL DEFAULT 0, approximate_cost_usd REAL NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS ai_cache (
        cache_key TEXT PRIMARY KEY, response_json TEXT NOT NULL, created_at TEXT NOT NULL
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
    `);
    const auditColumns = this.db.prepare('PRAGMA table_info(audits)').all() as Row[];
    if (!auditColumns.some((column) => column.name === 'options_json'))
      this.db.exec("ALTER TABLE audits ADD COLUMN options_json TEXT NOT NULL DEFAULT '{}'");
    if (!auditColumns.some((column) => column.name === 'workflow_version'))
      this.db.exec(
        "ALTER TABLE audits ADD COLUMN workflow_version TEXT NOT NULL DEFAULT 'traceward-audit-v1'",
      );
    this.db.exec('PRAGMA user_version = 4;');
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
      .prepare('INSERT INTO projects VALUES (?, ?, ?, ?)')
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
    };
  }
  projects(): Project[] {
    return (this.db.prepare('SELECT id FROM projects ORDER BY created_at DESC').all() as Row[]).map(
      (row) => this.project(String(row.id)),
    );
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
  reserveAiCall(
    auditId: string,
    estimatedInputTokens: number,
    limits: { calls: number; inputTokens: number; outputTokens: number; outputPerCall: number },
  ): { maximumOutputTokens: number } {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('INSERT OR IGNORE INTO ai_usage(audit_id) VALUES (?)').run(auditId);
      const usage = this.db
        .prepare('SELECT * FROM ai_usage WHERE audit_id = ?')
        .get(auditId) as Row;
      const remainingOutput = limits.outputTokens - Number(usage.output_tokens);
      if (Number(usage.calls) >= limits.calls) throw new Error('AI call budget exhausted.');
      if (Number(usage.input_tokens) + estimatedInputTokens > limits.inputTokens)
        throw new Error('AI input-token budget exhausted.');
      if (remainingOutput < 100) throw new Error('AI output-token budget exhausted.');
      this.db
        .prepare(
          'UPDATE ai_usage SET calls = calls + 1, input_tokens = input_tokens + ? WHERE audit_id = ?',
        )
        .run(estimatedInputTokens, auditId);
      this.db.exec('COMMIT');
      return { maximumOutputTokens: Math.min(limits.outputPerCall, remainingOutput) };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  finalizeAiCall(
    auditId: string,
    estimatedInputTokens: number,
    actual: { inputTokens: number; outputTokens: number; approximateCostUsd: number },
  ): void {
    this.db
      .prepare(
        `UPDATE ai_usage SET input_tokens = MAX(0, input_tokens - ? + ?),
         output_tokens = output_tokens + ?, approximate_cost_usd = approximate_cost_usd + ?
         WHERE audit_id = ?`,
      )
      .run(
        estimatedInputTokens,
        actual.inputTokens,
        actual.outputTokens,
        actual.approximateCostUsd,
        auditId,
      );
  }
  recordAiCacheHit(auditId: string): void {
    this.db.prepare('INSERT OR IGNORE INTO ai_usage(audit_id) VALUES (?)').run(auditId);
    this.db
      .prepare('UPDATE ai_usage SET cache_hits = cache_hits + 1 WHERE audit_id = ?')
      .run(auditId);
  }
  aiUsage(auditId: string): {
    calls: number;
    cacheHits: number;
    inputTokens: number;
    outputTokens: number;
    approximateCostUsd: number;
  } {
    const row = this.db.prepare('SELECT * FROM ai_usage WHERE audit_id = ?').get(auditId) as
      Row | undefined;
    return {
      calls: Number(row?.calls ?? 0),
      cacheHits: Number(row?.cache_hits ?? 0),
      inputTokens: Number(row?.input_tokens ?? 0),
      outputTokens: Number(row?.output_tokens ?? 0),
      approximateCostUsd: Number(row?.approximate_cost_usd ?? 0),
    };
  }
  readAiCache<T>(key: string, maximumAgeMs: number): T | null {
    const row = this.db.prepare('SELECT * FROM ai_cache WHERE cache_key = ?').get(key) as
      Row | undefined;
    if (!row || Date.now() - Date.parse(String(row.created_at)) > maximumAgeMs) return null;
    try {
      return JSON.parse(String(row.response_json)) as T;
    } catch {
      return null;
    }
  }
  saveAiCache(key: string, value: unknown): void {
    const serialized = JSON.stringify(value);
    if (serialized.length > 64 * 1024) throw new Error('AI cache entry is too large.');
    this.db
      .prepare(
        `INSERT INTO ai_cache(cache_key, response_json, created_at) VALUES (?, ?, ?)
         ON CONFLICT(cache_key) DO UPDATE SET response_json = excluded.response_json,
         created_at = excluded.created_at`,
      )
      .run(key, serialized, now());
  }
}
