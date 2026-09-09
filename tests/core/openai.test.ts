import test from 'node:test';
import assert from 'node:assert/strict';
import { configuration } from '../../src/server/config.ts';
import { AuditStore } from '../../src/server/store.ts';
import { scanPatterns } from '../../src/scanners/builtin.ts';
import { createOpenAiReviewer } from '../../src/engine/openai.ts';
import { snapshotOf } from '../helpers.ts';
import type { ContextDescriptor } from '../../src/engine/context-broker.ts';

function setup() {
  const store = new AuditStore(':memory:');
  const project = store.registerProject('OpenAI fixture', '/fixture/openai');
  const audit = store.enqueue(project.id);
  const finding = scanPatterns(snapshotOf('eval(input)'))[0]!;
  const config = {
    ...configuration(),
    aiMode: 'openai' as const,
    model: 'economical-fixture-model',
    strongModel: '',
    openaiApiKey: 'fixture-api-key-never-log',
    aiTimeoutMs: 1000,
    aiMaxRetries: 1,
    aiMaxCalls: 4,
    aiMaxCallsPerFinding: 2,
    aiInputTokenBudget: 10000,
    aiOutputTokenBudget: 2000,
    aiMaxOutputTokensPerCall: 500,
    openaiInputCostPerMillion: 1,
    openaiOutputCostPerMillion: 2,
  };
  return { store, audit, finding, config };
}

function success(evidenceId: string): Response {
  return Response.json({
    output_text: JSON.stringify({
      assessment: 'inconclusive',
      confidence: 'low',
      explanation: 'Runtime reachability is not available.',
      evidenceIds: [evidenceId],
      limitations: ['Only the supplied snapshot context was inspected.'],
      requestedContextIds: [],
    }),
    usage: {
      input_tokens: 120,
      output_tokens: 40,
      input_tokens_details: { cached_tokens: 0 },
    },
  });
}

test('OpenAI request is opt-in, structured, non-stored, redacted, and provenance-rich', async (context) => {
  const { store, audit, finding, config } = setup();
  context.after(() => store.close());
  let calls = 0;
  let requestBody = '';
  const reviewer = createOpenAiReviewer(config, store, audit.id, async (_input, init) => {
    calls++;
    requestBody = String(init?.body ?? '');
    return success(finding.evidence[0]!.id);
  });
  const source = 'const apiKey = "sensitive-fixture-value"; // developer@example.test';
  const available: ContextDescriptor[] = [
    { id: 'ctx-source', kind: 'symbol', label: 'example', file: 'src/example.ts', line: 1 },
    { id: 'ctx-env', kind: 'fact', label: 'env', file: '.env', line: 1 },
    { id: 'ctx-outside', kind: 'fact', label: 'outside', file: '../../outside', line: 1 },
  ];
  const first = await reviewer.assess(
    finding,
    source,
    available,
    ['ctx-source'],
  );
  const parsedBody = JSON.parse(requestBody) as Record<string, unknown>;
  assert.equal(parsedBody.store, false);
  assert.equal((parsedBody.text as { format: { type: string } }).format.type, 'json_schema');
  assert.equal('tools' in parsedBody, false);
  assert.ok(requestBody.includes('[REDACTED]'));
  assert.ok(!requestBody.includes('sensitive-fixture-value'));
  assert.ok(!requestBody.includes('developer@example.test'));
  assert.ok(!requestBody.includes('../../outside'));
  assert.equal(first.provider, 'openai');
  assert.equal(first.model, 'economical-fixture-model');
  assert.equal(first.redactionApplied, true);
  assert.deepEqual(first.tokenUsage, { inputTokens: 120, outputTokens: 40, cachedInputTokens: 0 });
  assert.ok((first.approximateCostUsd ?? 0) > 0);
  assert.equal(store.aiUsage(audit.id).calls, 1);

  const second = await reviewer.assess(
    finding,
    source,
    available.slice(0, 2),
    ['ctx-source'],
  );
  assert.equal(second.cached, true);
  assert.equal(calls, 1);
  assert.equal(store.aiUsage(audit.id).cacheHits, 1);
});

test('OpenAI retries are bounded and count against the audit budget', async (context) => {
  const { store, audit, finding, config } = setup();
  context.after(() => store.close());
  let calls = 0;
  const reviewer = createOpenAiReviewer(config, store, audit.id, async () => {
    calls++;
    return calls === 1 ? new Response('', { status: 500 }) : success(finding.evidence[0]!.id);
  });
  await reviewer.assess(
    finding,
    'bounded context',
    [{ id: 'ctx-source', kind: 'symbol', label: 'example', file: 'src/example.ts', line: 1 }],
    ['ctx-source'],
  );
  assert.equal(calls, 2);
  assert.equal(store.aiUsage(audit.id).calls, 2);
});

test('OpenAI malformed output and hard call budgets fail closed', async (context) => {
  const { store, audit, finding, config } = setup();
  context.after(() => store.close());
  const malformed = createOpenAiReviewer(
    { ...config, aiMaxRetries: 0 },
    store,
    audit.id,
    async () =>
      Response.json({ output_text: '{not-json', usage: { input_tokens: 5, output_tokens: 2 } }),
  );
  await assert.rejects(
    () =>
      malformed.assess(
        finding,
        'context',
        [{ id: 'ctx-source', kind: 'symbol', label: 'example', file: 'src/example.ts', line: 1 }],
        ['ctx-source'],
      ),
    /JSON/,
  );

  const secondFinding = { ...finding, id: 'another-finding', fingerprint: 'another-fingerprint' };
  const exhausted = createOpenAiReviewer(
    { ...config, aiMaxCalls: 1, aiMaxRetries: 0 },
    store,
    audit.id,
    async () => success(secondFinding.evidence[0]!.id),
  );
  await assert.rejects(
    () =>
      exhausted.assess(
        secondFinding,
        'context',
        [{ id: 'ctx-source', kind: 'symbol', label: 'example', file: 'src/example.ts', line: 1 }],
        ['ctx-source'],
      ),
    /budget exhausted/,
  );
});

test('OpenAI timeout is bounded', async (context) => {
  const { store, audit, finding, config } = setup();
  context.after(() => store.close());
  const reviewer = createOpenAiReviewer(
    { ...config, aiTimeoutMs: 50, aiMaxRetries: 0 },
    store,
    audit.id,
    async (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      }),
  );
  await assert.rejects(
    () =>
      reviewer.assess(
        finding,
        'context',
        [{ id: 'ctx-source', kind: 'symbol', label: 'example', file: 'src/example.ts', line: 1 }],
        ['ctx-source'],
      ),
    /aborted/,
  );
});
