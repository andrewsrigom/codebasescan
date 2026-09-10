import test from 'node:test';
import assert from 'node:assert/strict';
import { AuditStore } from '../../src/server/store.ts';
import { sampleReport } from '../helpers.ts';
function setup() {
  const store = new AuditStore(':memory:');
  const project = store.registerProject('Example', '/fixture/project');
  return { store, project };
}
test('only one active audit can exist for each project', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  store.enqueue(project.id);
  assert.throws(() => store.enqueue(project.id), /active audit/);
});
test('claim is atomic and increments an attempt', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  assert.equal(store.claim()?.id, audit.id);
  assert.equal(store.audit(audit.id).attempts, 1);
  assert.equal(store.claim(), null);
});
test('audit options are persisted with the queued run', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id, {
    httpProbe: { url: 'http://127.0.0.1:3000/', allowPrivateNetwork: false },
    gitHistorySecrets: true,
    modes: ['security', 'privacy'],
    scopePreflight: {
      schemaVersion: 1,
      estimatedAt: '2026-09-09T00:00:00.000Z',
      supportedFiles: 12,
      supportedBytes: 4096,
      oversizedFiles: 0,
      visitedEntries: 20,
      predictedTruncated: false,
      reasons: [],
      limits: { files: 1500, bytesPerFile: 262144, totalBytes: 8388608 },
      truncationApproved: false,
    },
  });
  assert.equal(store.audit(audit.id).options.httpProbe?.url, 'http://127.0.0.1:3000/');
  assert.equal(store.audit(audit.id).options.gitHistorySecrets, true);
  assert.deepEqual(store.audit(audit.id).options.modes, ['security', 'privacy']);
  assert.equal(store.audit(audit.id).options.scopePreflight?.supportedFiles, 12);
});
test('cancellation cannot be overwritten by a late worker completion', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.claim();
  store.cancel(audit.id);
  store.transition(audit.id, 'completed');
  store.saveProgress(audit.id, sampleReport());
  assert.equal(store.audit(audit.id).status, 'cancelled');
  assert.equal(store.audit(audit.id).report, null);
});
test('publication is an explicit state transition and cannot race twice', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.claim();
  store.saveProgress(audit.id, sampleReport());
  store.transition(audit.id, 'awaiting_review');
  store.publish(audit.id, 'Reviewed scope and remaining unknowns.');
  assert.equal(store.audit(audit.id).status, 'queued');
  assert.throws(() => store.publish(audit.id, 'A duplicate publication request.'));
});
test('human review preserves findings instead of deleting them', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.claim();
  const report = sampleReport();
  store.saveProgress(audit.id, report);
  store.transition(audit.id, 'awaiting_review');
  store.reviewFinding(audit.id, {
    findingId: report.findings[0]!.id,
    disposition: 'false_positive',
    note: 'Inspected the call site; input is a fixed internal literal.',
  });
  assert.equal(store.audit(audit.id).report?.findings.length, 1);
  assert.equal(store.audit(audit.id).report?.findings[0]?.disposition, 'false_positive');
  const revisions = store.reportRevisions(audit.id);
  assert.equal(revisions.length, 2);
  assert.equal(revisions[0]?.source, 'workflow');
  assert.equal(revisions[0]?.report.findings[0]?.disposition, 'needs_review');
  assert.equal(revisions[1]?.source, 'human-review');
  assert.equal(revisions[1]?.report.findings[0]?.disposition, 'false_positive');
});
test('project exceptions retain findings and propagate only while active', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.claim();
  const report = sampleReport();
  store.saveProgress(audit.id, report);
  store.transition(audit.id, 'awaiting_review');
  const finding = report.findings[0]!;
  store.suppressFinding(audit.id, {
    findingId: finding.id,
    reason: 'Accepted test fixture for this project only.',
    expiresAt: '2099-01-01T00:00:00.000Z',
  });
  assert.equal(
    store.audit(audit.id).report?.findings[0]?.suppression?.expiresAt,
    '2099-01-01T00:00:00.000Z',
  );
  assert.equal(
    store.applySuppressions(project.id, [finding])[0]?.suppression?.reason,
    'Accepted test fixture for this project only.',
  );
  store.db
    .prepare('UPDATE project_suppressions SET expires_at = ? WHERE project_id = ?')
    .run('2000-01-01T00:00:00.000Z', project.id);
  assert.equal(store.applySuppressions(project.id, [finding])[0]?.suppression, undefined);
});

test('a completed audit can become the explicit project baseline', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.claim();
  store.saveProgress(audit.id, sampleReport());
  store.transition(audit.id, 'completed');
  store.setProjectBaseline(project.id, audit.id);
  assert.equal(store.project(project.id).baselineAuditId, audit.id);
  assert.equal(store.projectBaseline(project.id)?.id, audit.id);
});
test('human control review is appended without changing deterministic checklist state', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.claim();
  const report = sampleReport();
  report.checklist = {
    schemaVersion: 1,
    packId: 'traceward-web-application',
    packVersion: 'fixture',
    controls: [
      {
        id: 'TW-CTRL-AUTHN-001',
        domain: 'authentication',
        title: 'Authentication control',
        status: 'UNVERIFIED',
        rationale: 'Runtime gateway evidence is outside the snapshot.',
        applicability: 'Applies to sensitive routes.',
        evidence: [],
        verification: 'Inspect and test the gateway policy.',
        limitations: [],
      },
    ],
    summary: {
      EVIDENCED: 0,
      GAP_CANDIDATE: 0,
      UNVERIFIED: 1,
      NOT_APPLICABLE: 0,
      PARTIAL: 0,
      FAILED: 0,
    },
  };
  store.saveProgress(audit.id, report);
  store.transition(audit.id, 'awaiting_review');
  store.reviewControl(audit.id, {
    controlId: 'TW-CTRL-AUTHN-001',
    decision: 'verified_external',
    note: 'Gateway policy was inspected and exercised with an unauthorized request.',
  });
  const control = store.audit(audit.id).report?.checklist?.controls[0];
  assert.equal(control?.status, 'UNVERIFIED');
  assert.equal(control?.review?.decision, 'verified_external');
  assert.equal(store.reportRevisions(audit.id).at(-1)?.source, 'human-review');
});
test('invalid reports fail validation on write and read', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.claim();
  assert.throws(() => store.saveProgress(audit.id, { schemaVersion: 3 } as never), /Invalid input/);
  store.saveProgress(audit.id, sampleReport());
  store.db.prepare('UPDATE audits SET report_json = ? WHERE id = ?').run('{}', audit.id);
  assert.throws(() => store.audit(audit.id), /Invalid input/);
});
test('database schema migration records the current version', (context) => {
  const { store } = setup();
  context.after(() => store.close());
  const version = store.db.prepare('PRAGMA user_version').get() as { user_version: number };
  assert.equal(version.user_version, 5);
});
test('a second worker in a live local process is rejected', (context) => {
  const { store } = setup();
  context.after(() => store.close());
  const token = store.acquireWorker();
  assert.throws(() => store.acquireWorker(), /already running/);
  store.releaseWorker(token);
  const next = store.acquireWorker();
  store.releaseWorker(next);
});
test('a new worker recovers an audit abandoned by a dead process', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.claim();
  store.db
    .prepare('INSERT INTO worker_lock VALUES (?, ?, ?, ?)')
    .run('local', 'dead-worker', 2147483646, new Date().toISOString());

  const token = store.acquireWorker();
  assert.equal(store.audit(audit.id).status, 'queued');
  assert.match(store.audit(audit.id).error ?? '', /Previous worker stopped/);
  store.releaseWorker(token);
});
test('workflow events are idempotent by event key', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.event(audit.id, 'scan', 'scan', 'First run.');
  store.event(audit.id, 'scan', 'scan', 'Replayed run.');
  assert.equal(store.events(audit.id).filter((event) => event.stage === 'scan').length, 1);
});
