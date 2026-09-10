import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { AuditStore } from '../../src/server/store.ts';

test('an unfinished AI reservation survives database reopen and still limits cost', async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-ai-budget-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const databasePath = path.join(directory, 'application.sqlite');
  const first = new AuditStore(databasePath);
  const project = first.registerProject('Budget fixture', '/fixture/ai-budget');
  const audit = first.enqueue(project.id);
  const limits = { calls: 1, inputTokens: 1_000, outputTokens: 500, outputPerCall: 200 };
  first.reserveAiCall(audit.id, 400, limits);
  first.close();

  const reopened = new AuditStore(databasePath);
  context.after(() => reopened.close());
  assert.deepEqual(reopened.aiUsage(audit.id), {
    calls: 1,
    cacheHits: 0,
    inputTokens: 400,
    outputTokens: 0,
    approximateCostUsd: 0,
  });
  assert.throws(() => reopened.reserveAiCall(audit.id, 1, limits), /call budget exhausted/);
});
