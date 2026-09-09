import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateReports } from '../../src/domain/evaluation.ts';
import { sampleReport } from '../helpers.ts';

test('evaluation aggregates anonymized human outcomes without accuracy claims', () => {
  const confirmed = sampleReport();
  confirmed.findings[0]!.disposition = 'confirmed';
  confirmed.findings[0]!.review = {
    decision: 'confirmed',
    note: 'Request input reaches the dynamic execution sink in the tested route.',
    at: '2026-09-09T12:00:00.000Z',
  };
  confirmed.aiUsage = {
    provider: 'openai',
    models: ['fixture-model'],
    calls: 1,
    cacheHits: 0,
    inputTokens: 100,
    outputTokens: 20,
    approximateCostUsd: 0.01,
    contextFilesSent: ['src/example.ts'],
    redactionApplied: true,
  };
  confirmed.checklist = {
    controls: [
      {
        review: {
          decision: 'verified_external',
          note: 'Gateway policy was inspected and tested.',
          at: '2026-09-09T12:00:00.000Z',
        },
      },
    ],
  } as NonNullable<typeof confirmed.checklist>;
  const falsePositive = sampleReport();
  falsePositive.auditId = '00000000-0000-4000-8000-000000000002';
  falsePositive.findings[0]!.disposition = 'false_positive';
  falsePositive.findings[0]!.review = {
    decision: 'false_positive',
    note: 'The source is a fixed internal expression selected by trusted code.',
    at: '2026-09-09T13:00:00.000Z',
  };
  const result = evaluateReports([confirmed, falsePositive]);
  assert.equal(result.reports, 2);
  assert.equal(result.confirmedFindings, 1);
  assert.equal(result.falsePositives, 1);
  assert.equal(result.fixedFindings, 0);
  assert.equal(result.approximateAiCostPerConfirmedFindingUsd, 0.01);
  assert.equal(result.reviewedControls, 1);
  assert.equal(result.controlReviews.verified_external, 1);
  assert.equal(result.ruleOutcomes[0]?.candidates, 2);
  assert.ok(!JSON.stringify(result).includes('projectName'));
  assert.ok(result.warning.includes('false negatives'));
});

test('evaluation requires at least one report', () => {
  assert.throws(() => evaluateReports([]), /At least one/);
});
