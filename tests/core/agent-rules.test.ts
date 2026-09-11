import assert from 'node:assert/strict';
import test from 'node:test';
import {
  agentReviewRulePack,
  parseAgentReviewRulePack,
  reviewRulesForFinding,
} from '../../src/domain/agent-rules.ts';
import type { Finding } from '../../src/domain/types.ts';
import { sampleReport } from '../helpers.ts';

const categories: Finding['category'][] = [
  'authentication',
  'authorization',
  'injection',
  'secrets',
  'configuration',
  'ai-security',
  'dependencies',
  'accessibility',
  'privacy',
  'reliability',
  'code',
];

test('agent review rule pack is strict, versioned, and covers every finding category', () => {
  assert.deepEqual(parseAgentReviewRulePack(agentReviewRulePack), agentReviewRulePack);
  assert.equal(agentReviewRulePack.schemaVersion, 1);
  assert.equal(
    new Set(agentReviewRulePack.rules.map((rule) => rule.id)).size,
    agentReviewRulePack.rules.length,
  );

  const base = sampleReport().findings[0]!;
  for (const category of categories) {
    const finding = { ...base, category };
    assert.ok(reviewRulesForFinding(finding).length > 0, `missing review rule for ${category}`);
  }
});

test('agent review rules contain evidence, false-positive, search, and limitation guidance', () => {
  for (const rule of agentReviewRulePack.rules) {
    assert.ok(rule.questions.length >= 2);
    assert.ok(rule.evidenceRequired.length >= 1);
    assert.ok(rule.falsePositiveChecks.length >= 1);
    assert.ok(rule.searchHints.length >= 1);
    assert.ok(rule.limitations.length >= 1);
  }
});
