import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRuleQualityReport } from '../../src/domain/rule-quality.ts';
import {
  parseRuleQualityReport,
  ruleQualityJsonSchema,
} from '../../src/domain/rule-quality-schema.ts';
import { sampleReport } from '../helpers.ts';

test('rule quality groups applied findings and preserves human dispositions', () => {
  const report = sampleReport();
  report.findings.push({
    ...structuredClone(report.findings[0]!),
    id: 'finding-copy',
    disposition: 'false_positive',
  });

  const quality = parseRuleQualityReport(buildRuleQualityReport(report));
  assert.equal(quality.kind, 'traceward-rule-quality');
  assert.equal(quality.auditId, report.auditId);
  assert.equal(quality.summary.appliedRules, 1);
  assert.equal(quality.summary.withHumanDisposition, 1);
  assert.equal(quality.rules[0]?.observedFindings, 2);
  assert.equal(quality.rules[0]?.humanDispositions.false_positive, 1);
  assert.ok(quality.rules[0]?.limitations.length);
});

test('rule quality exposes measured and explicitly unmeasured fixture status', () => {
  const report = sampleReport();
  const knownFalsePositive = buildRuleQualityReport(report);
  assert.equal(knownFalsePositive.rules[0]?.declaredFixtureMetrics.status, 'known_false_positive');

  report.findings[0] = {
    ...report.findings[0]!,
    ruleId: 'TW-001',
  };
  const measured = buildRuleQualityReport(report);
  assert.equal(measured.rules[0]?.declaredFixtureMetrics.status, 'measured');

  report.findings[0] = {
    ...report.findings[0]!,
    ruleId: 'TW-UNMEASURED',
  };
  const unmeasured = buildRuleQualityReport(report);
  assert.equal(unmeasured.rules[0]?.declaredFixtureMetrics.status, 'not_measured');
});

test('rule quality JSON Schema is versioned', () => {
  const schema = ruleQualityJsonSchema() as {
    properties?: { schemaVersion?: { const?: number } };
  };
  assert.equal(schema.properties?.schemaVersion?.const, 1);
});
