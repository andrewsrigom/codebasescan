import test from 'node:test';
import assert from 'node:assert/strict';
import { EphemeralAuditStore } from '../../src/engine/ephemeral-audit-store.ts';
import { sampleReport } from '../helpers.ts';

test('ephemeral audit store supports one-shot lifecycle without SQLite', () => {
  const store = new EphemeralAuditStore();
  const project = store.registerProject('fixture', '/tmp/fixture');
  const queued = store.enqueue(project.id);

  assert.equal(store.claim(queued.id)?.status, 'running');
  const report = { ...sampleReport(), auditId: queued.id, projectName: project.name };
  store.saveProgress(queued.id, report);
  store.transition(queued.id, 'completed');

  const completed = store.audit(queued.id);
  assert.equal(completed.status, 'completed');
  assert.equal(completed.report?.auditId, queued.id);
  assert.deepEqual(store.applySuppressions(project.id, report.findings), report.findings);
});
