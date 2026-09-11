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

test('ephemeral audit store keeps AI budgets and cache bounded', () => {
  const store = new EphemeralAuditStore();
  const project = store.registerProject('fixture', '/tmp/fixture');
  const audit = store.enqueue(project.id);

  assert.deepEqual(
    store.reserveAiCall(audit.id, 20, {
      calls: 1,
      inputTokens: 100,
      outputTokens: 200,
      outputPerCall: 150,
    }),
    { maximumOutputTokens: 150 },
  );
  assert.throws(
    () =>
      store.reserveAiCall(audit.id, 20, {
        calls: 1,
        inputTokens: 100,
        outputTokens: 200,
        outputPerCall: 150,
      }),
    /call budget/,
  );
  store.finalizeAiCall(audit.id, 20, {
    inputTokens: 18,
    outputTokens: 12,
    approximateCostUsd: 0.01,
  });
  store.recordAiCacheHit(audit.id);
  assert.deepEqual(store.aiUsage(audit.id), {
    calls: 1,
    cacheHits: 1,
    inputTokens: 18,
    outputTokens: 12,
    approximateCostUsd: 0.01,
  });

  store.saveAiCache('key', { assessment: 'bounded' });
  assert.deepEqual(store.readAiCache('key', 1_000), { assessment: 'bounded' });
});
