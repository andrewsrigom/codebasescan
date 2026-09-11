import test from 'node:test';
import assert from 'node:assert/strict';
import { agentReviewDepthLimits, parseAgentReviewDepth } from '../../src/domain/agent-depth.ts';

test('agent review depth defaults to standard and deep expands bounded work', () => {
  assert.equal(parseAgentReviewDepth(undefined), 'standard');
  assert.equal(parseAgentReviewDepth('quick'), 'quick');
  assert.equal(parseAgentReviewDepth('deep'), 'deep');
  assert.ok(
    agentReviewDepthLimits.deep.maximumContextCharacters >
      agentReviewDepthLimits.standard.maximumContextCharacters,
  );
  assert.ok(
    agentReviewDepthLimits.standard.maximumContextCharacters >
      agentReviewDepthLimits.quick.maximumContextCharacters,
  );
  assert.ok(agentReviewDepthLimits.deep.maximumRounds <= 4);
  assert.throws(() => parseAgentReviewDepth('unlimited'), /quick, standard, or deep/);
});
