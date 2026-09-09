import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { MemorySaver, Command } from '@langchain/langgraph';
import { buildAuditGraph } from '../../src/engine/audit-graph.ts';
import { buildReviewGraph } from '../../src/engine/review-graph.ts';
import { AuditStore } from '../../src/server/store.ts';
import { configuration } from '../../src/server/config.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import { scanPatterns } from '../../src/scanners/builtin.ts';
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
  const config = { ...configuration(), dataDirectory: directory, temporaryDirectory: path.join(directory, 'temporary'), aiMode: 'disabled' as const, semgrep: false, gitleaks: false };
  const graph = buildAuditGraph({ root, projectName: project.name, config, store, checkpointer: new MemorySaver(), reviewer: null });
  const invocation = { configurable: { thread_id: audit.id }, recursionLimit: 100 };
  await graph.invoke({ auditId: audit.id }, invocation);
  const paused = await graph.getState(invocation);
  assert.ok(paused.next.includes('human_review'));
  assert.equal(store.audit(audit.id).report?.findings.length, 7);
  assert.equal(store.audit(audit.id).report?.scanners.length, 4);
  await graph.invoke(new Command({ resume: { note: 'Reviewed the fixture; findings remain unconfirmed.' } }), invocation);
  assert.equal((await graph.getState(invocation)).next.length, 0);
  assert.equal(store.audit(audit.id).report?.publication, 'reviewed');
  assert.ok(store.audit(audit.id).report?.findings.every((finding) => finding.disposition === 'needs_review'));
});
test('the context loop terminates after two rounds with an injected reviewer', async () => {
  const source = await captureSnapshot(path.resolve('fixtures/review-worthy-saas'));
  const finding = scanPatterns(source).find((candidate) => candidate.category === 'injection')!;
  let calls = 0;
  const graph = buildReviewGraph(source, {
    async assess() {
      calls++;
      return { assessment: 'inconclusive', explanation: 'More runtime evidence is needed.', evidenceIds: [], limitations: ['Runtime is outside the snapshot.'], requestedFiles: source.files.filter((file) => !finding.evidence.some((evidence) => evidence.file === file.path)).slice(calls - 1, calls).map((file) => file.path) };
    }
  });
  const result = await graph.invoke({ finding });
  assert.ok(calls <= 2);
  assert.equal(result.rounds, 2);
});
test('SQLite checkpoints survive graph reconstruction between review and resume', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'traceward-persistence-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const store = new AuditStore(path.join(directory, 'app.sqlite'));
  context.after(() => store.close());
  const project = store.registerProject('Persistence fixture', path.resolve('fixtures/hardened-saas'));
  const audit = store.enqueue(project.id);
  store.claim();
  const config = { ...configuration(), checkpointPath: path.join(directory, 'checkpoints.sqlite'), temporaryDirectory: path.join(directory, 'temporary'), aiMode: 'disabled' as const, semgrep: false, gitleaks: false };
  await executeAudit(store, audit.id, config);
  assert.equal(store.audit(audit.id).status, 'awaiting_review');
  store.publish(audit.id, 'Reviewed static coverage; not a security certification.');
  store.claim();
  await executeAudit(store, audit.id, config);
  assert.equal(store.audit(audit.id).status, 'completed');
});
