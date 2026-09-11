import assert from 'node:assert/strict';
import test from 'node:test';
import type { Finding } from '../../src/domain/types.ts';
import {
  humanFindingImpact,
  humanFindingLimitations,
  humanFindingSource,
  humanVerificationSteps,
} from '../../src/domain/finding-guidance.ts';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
    fingerprint: 'f'.repeat(64),
    ruleId: 'TW-NEXT006',
    source: 'next',
    title: 'Missing validation',
    category: 'configuration',
    severity: 'medium',
    sourceSeverity: 'MEDIUM',
    description: 'A mutation has no mapped validation.',
    remediation: 'Validate input at the boundary.',
    cwe: ['CWE-20'],
    evidence: [],
    disposition: 'needs_review',
    ...overrides,
  };
}

test('finding guidance translates detector data into human review language', () => {
  const candidate = finding();
  assert.equal(humanFindingSource(candidate.source), 'Next.js check');
  assert.match(humanFindingImpact(candidate), /does not establish runtime exploitability/);
  assert.match(humanVerificationSteps(candidate)[0]!, /effective environment/);
  assert.deepEqual(humanFindingLimitations(candidate), [
    'Review the cited evidence and scanner coverage before deciding.',
  ]);
});

test('finding guidance preserves explicit rule and contextual limitations without duplicates', () => {
  const candidate = finding({
    analysis: {
      kind: 'deterministic',
      assessment: 'needs_review',
      explanation: 'The code path needs review.',
      inspectedFiles: [],
      evidenceIds: [],
      rounds: 1,
      limitations: ['Only static source was inspected.', 'Shared limitation.'],
    },
  });
  assert.deepEqual(humanFindingLimitations(candidate, ['Shared limitation.']), [
    'Shared limitation.',
    'Only static source was inspected.',
  ]);
});
