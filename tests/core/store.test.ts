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
  store.reviewFinding(audit.id, { findingId: report.findings[0]!.id, disposition: 'false_positive', note: 'Inspected the call site; input is a fixed internal literal.' });
  assert.equal(store.audit(audit.id).report?.findings.length, 1);
  assert.equal(store.audit(audit.id).report?.findings[0]?.disposition, 'false_positive');
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
