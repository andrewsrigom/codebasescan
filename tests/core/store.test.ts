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
  });
  assert.equal(store.audit(audit.id).options.httpProbe?.url, 'http://127.0.0.1:3000/');
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
  assert.equal(version.user_version, 3);
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
test('workflow events are idempotent by event key', (context) => {
  const { store, project } = setup();
  context.after(() => store.close());
  const audit = store.enqueue(project.id);
  store.event(audit.id, 'scan', 'scan', 'First run.');
  store.event(audit.id, 'scan', 'scan', 'Replayed run.');
  assert.equal(store.events(audit.id).filter((event) => event.stage === 'scan').length, 1);
});
