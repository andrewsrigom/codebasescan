import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { MemorySaver, Command, INTERRUPT } from '@langchain/langgraph';
import { buildAuditGraph } from '../../src/engine/audit-graph.ts';
import { buildReviewGraph } from '../../src/engine/review-graph.ts';
import { AuditStore } from '../../src/server/store.ts';
import { configuration } from '../../src/server/config.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import { scanPatterns } from '../../src/scanners/builtin.ts';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { executeAudit } from '../../src/engine/run.ts';
import { disableRemoteTracing } from '../../src/security/privacy.ts';
disableRemoteTracing();
test('LangGraph fans in scanner results and pauses for publication review', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-graph-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuditStore(':memory:');
  context.after(() => store.close());
  const root = path.resolve('fixtures/review-worthy-saas');
  const project = store.registerProject('Graph fixture', root);
  const audit = store.enqueue(project.id);
  store.claim();
  const config = {
    ...configuration(),
    dataDirectory: directory,
    temporaryDirectory: path.join(directory, 'temporary'),
    aiMode: 'disabled' as const,
    semgrep: false,
    gitleaks: false,
  };
  const graph = buildAuditGraph({
    root,
    projectName: project.name,
    config,
    store,
    checkpointer: new MemorySaver(),
    reviewer: null,
  });
  const invocation = {
    configurable: { thread_id: audit.id },
    recursionLimit: 100,
    durability: 'sync' as const,
  };
  const result = await graph.invoke({ auditId: audit.id }, invocation);
  assert.ok(graph.isInterrupted(result));
  const interruptId = result[INTERRUPT][0]?.id;
  assert.ok(interruptId);
  let interruptedCheckpointId: string | undefined;
  for await (const snapshot of graph.getStateHistory(invocation, { limit: 100 })) {
    if (snapshot.tasks.some((task) => task.interrupts.some((item) => item.id === interruptId))) {
      interruptedCheckpointId = snapshot.config.configurable?.checkpoint_id as string | undefined;
      break;
    }
  }
  assert.ok(interruptedCheckpointId);
  assert.equal(store.audit(audit.id).report?.findings.length, 9);
  assert.equal(store.audit(audit.id).report?.scanners.length, 12);
  assert.ok(
    store.audit(audit.id).report?.scanners.some((scanner) => scanner.id === 'react-security'),
  );
  assert.ok(
    store.audit(audit.id).report?.scanners.some((scanner) => scanner.id === 'next-security'),
  );
  assert.equal(store.audit(audit.id).report?.projectProfile?.status, 'complete');
  assert.equal(store.audit(audit.id).report?.schemaVersion, 4);
  assert.ok(store.audit(audit.id).report?.mechanicalAnalysis?.architecture);
  assert.ok(store.audit(audit.id).report?.mechanicalAnalysis?.duplication);
  assert.equal(store.audit(audit.id).report?.checklist?.packId, 'traceward-web-application');
  const reviewedControl = store.audit(audit.id).report?.checklist?.controls[0];
  assert.ok(reviewedControl);
  store.transition(audit.id, 'awaiting_review');
  store.reviewControl(audit.id, {
    controlId: reviewedControl.id,
    decision: 'needs_follow_up',
    note: 'Runtime enforcement remains outside this source-only fixture.',
  });
  store.transition(audit.id, 'running');
  const resumed = await graph.invoke(
    new Command({
      resume: {
        [interruptId]: { note: 'Reviewed the fixture; findings remain unconfirmed.' },
      },
    }),
    {
      ...invocation,
      configurable: { ...invocation.configurable, checkpoint_id: interruptedCheckpointId },
    },
  );
  assert.equal(graph.isInterrupted(resumed), false);
  assert.equal(store.audit(audit.id).report?.publication, 'reviewed');
  assert.equal(
    store.audit(audit.id).report?.checklist?.controls[0]?.review?.decision,
    'needs_follow_up',
  );
  assert.ok(
    store
      .audit(audit.id)
      .report?.findings.every((finding) => finding.disposition === 'needs_review'),
  );
  assert.ok(
    store.audit(audit.id).report?.findings.every((finding) => finding.analysis === undefined),
  );
  assert.equal(store.events(audit.id).filter((item) => item.stage === 'investigate').length, 0);
});
test('the context loop terminates after two rounds with an injected reviewer', async () => {
  const source = await captureSnapshot(path.resolve('fixtures/review-worthy-saas'));
  const finding = scanPatterns(source).find((candidate) => candidate.category === 'injection')!;
  const profile = profileProject(source).profile;
  let calls = 0;
  const graph = buildReviewGraph(
    source,
    {
      provider: 'ollama',
      async assess(_finding, _context, availableContexts, contextIds) {
        calls++;
        return {
          assessment: 'inconclusive',
          confidence: 'low',
          explanation: 'More runtime evidence is needed.',
          evidenceIds: [],
          controlsFound: [],
          missingEvidence: ['Runtime authorization policy is outside the snapshot.'],
          impact: 'Impact depends on whether untrusted input reaches the operation.',
          preconditions: ['The route must be reachable.'],
          remediationOptions: ['Add an explicit trust-boundary guard.'],
          verificationPlan: ['Exercise the route with unauthorized fixture input.'],
          limitations: ['Runtime is outside the snapshot.'],
          requestedContextIds: availableContexts
            .filter((item) => !contextIds.includes(item.id))
            .slice(0, 1)
            .map((item) => item.id),
        };
      },
    },
    profile,
  );
  const result = await graph.invoke({ finding });
  assert.ok(calls <= 2);
  assert.equal(result.rounds, 2);
});
test('SQLite checkpoints survive graph reconstruction between review and resume', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-persistence-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuditStore(path.join(directory, 'app.sqlite'));
  context.after(() => store.close());
  const project = store.registerProject(
    'Persistence fixture',
    path.resolve('fixtures/hardened-saas'),
  );
  const audit = store.enqueue(project.id);
  store.claim();
  const config = {
    ...configuration(),
    checkpointPath: path.join(directory, 'checkpoints.sqlite'),
    temporaryDirectory: path.join(directory, 'temporary'),
    aiMode: 'disabled' as const,
    semgrep: false,
    gitleaks: false,
  };
  await executeAudit(store, audit.id, config);
  assert.equal(store.audit(audit.id).status, 'awaiting_review');
  store.publish(audit.id, 'Reviewed static coverage; not a security certification.');
  store.claim();
  await executeAudit(store, audit.id, config);
  assert.equal(store.audit(audit.id).status, 'completed');
});
test('checkpoint resume rejects changed execution config and workflow versions', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-checkpoint-version-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuditStore(path.join(directory, 'app.sqlite'));
  context.after(() => store.close());
  const project = store.registerProject(
    'Checkpoint version fixture',
    path.resolve('fixtures/hardened-saas'),
  );
  const config = {
    ...configuration(),
    dataDirectory: directory,
    checkpointPath: path.join(directory, 'checkpoints.sqlite'),
    temporaryDirectory: path.join(directory, 'temporary'),
    aiMode: 'disabled' as const,
    semgrep: false,
    gitleaks: false,
    osv: false,
  };
  const audit = store.enqueue(project.id);
  store.claim(audit.id);
  await executeAudit(store, audit.id, config);
  store.publish(audit.id, 'Reviewed checkpoint compatibility before publication.');
  store.claim(audit.id);
  await assert.rejects(
    () => executeAudit(store, audit.id, { ...config, osv: true }),
    /configuration changed/,
  );
  store.transition(audit.id, 'failed', 'Expected compatibility fixture failure.');

  const incompatible = store.enqueue(project.id);
  store.claim(incompatible.id);
  store.db
    .prepare('UPDATE audits SET workflow_version = ? WHERE id = ?')
    .run('traceward-audit-legacy', incompatible.id);
  await assert.rejects(
    () => executeAudit(store, incompatible.id, config),
    /workflow .* incompatible/,
  );
});
test('AI-disabled audits make zero AI or advisory network calls', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-no-network-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuditStore(path.join(directory, 'app.sqlite'));
  context.after(() => store.close());
  const project = store.registerProject('Offline fixture', path.resolve('fixtures/hardened-saas'));
  const audit = store.enqueue(project.id);
  store.claim();
  let calls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    throw new Error('Network must not be used.');
  };
  context.after(() => {
    globalThis.fetch = originalFetch;
  });
  await executeAudit(store, audit.id, {
    ...configuration(),
    dataDirectory: directory,
    checkpointPath: path.join(directory, 'checkpoints.sqlite'),
    temporaryDirectory: path.join(directory, 'temporary'),
    aiMode: 'disabled',
    semgrep: false,
    gitleaks: false,
    osv: false,
  });
  assert.equal(calls, 0);
  assert.equal(store.audit(audit.id).status, 'awaiting_review');
});
