import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { createContextBroker, contextBrokerLimits } from '../../src/engine/context-broker.ts';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import { scanPatterns } from '../../src/scanners/builtin.ts';

test('context broker resolves opaque evidence and profile IDs from the immutable snapshot', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/review-worthy-saas'));
  const finding = scanPatterns(snapshot).find((item) => item.ruleId === 'TW-003')!;
  const profile = profileProject(snapshot).profile;
  const broker = createContextBroker(snapshot, finding, profile);
  const evidenceId = finding.evidence[0]!.id;
  const initial = broker.collect(broker.initialIds, [], 0, true);
  assert.deepEqual(initial.deliveredIds, [evidenceId]);
  assert.ok(initial.context.includes(`"contextId":"${evidenceId}"`));
  assert.ok(initial.context.includes('eval(expression)'));

  const symbol = broker.catalog.find(
    (item) => item.kind === 'symbol' && item.file === finding.evidence[0]!.file,
  );
  assert.ok(symbol);
  const related = broker.collect([symbol.id], initial.deliveredIds, initial.characters);
  assert.deepEqual(related.deliveredIds, [symbol.id]);
  assert.ok(related.context.includes('evaluateExpression'));
});

test('context broker rejects unknown, repeated, path-shaped, and excess requests', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/review-worthy-saas'));
  const finding = scanPatterns(snapshot).find((item) => item.ruleId === 'TW-003')!;
  const broker = createContextBroker(snapshot, finding, profileProject(snapshot).profile);
  const allowed = broker.catalog.filter((item) => item.kind !== 'evidence').slice(0, 4);
  assert.ok(allowed.length >= 1);
  const delivery = broker.collect([
    finding.evidence[0]!.file,
    '../../outside',
    'unknown-id',
    ...allowed.map((item) => item.id),
  ]);
  assert.ok(delivery.deliveredIds.length <= contextBrokerLimits.maximumRequestedItems);
  assert.ok(!delivery.deliveredIds.includes('../../outside'));
  const repeated = broker.collect(
    delivery.deliveredIds,
    delivery.deliveredIds,
    delivery.characters,
  );
  assert.deepEqual(repeated.deliveredIds, []);
});

test('context broker keeps prompt injection as redacted bounded repository data', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/prompt-injection'));
  const finding = scanPatterns(snapshot)[0]!;
  const broker = createContextBroker(snapshot, finding, profileProject(snapshot).profile);
  const delivery = broker.collect(broker.initialIds, [], 0, true);
  assert.ok(delivery.characters <= contextBrokerLimits.maximumContextCharacters);
  assert.ok(delivery.context.includes('untrusted_repository_data'));
  assert.ok(!delivery.context.includes('sk-test-secret-value'));
});
