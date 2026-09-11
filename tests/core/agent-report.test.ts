import assert from 'node:assert/strict';
import test from 'node:test';
import { buildAgentReport } from '../../src/domain/agent-report.ts';
import { agentReportJsonSchema, parseAgentReport } from '../../src/domain/agent-report-schema.ts';
import { sampleReport } from '../helpers.ts';

test('agent report combines the remediation plan with review and discovery rules', () => {
  const report = sampleReport();
  const agentReport = buildAgentReport(report);
  assert.deepEqual(parseAgentReport(agentReport), agentReport);
  assert.equal(agentReport.kind, 'codebasescan-agent-report');
  assert.equal(agentReport.purpose, 'review_and_discovery');
  assert.equal(agentReport.summary.tasks, agentReport.plan.tasks.length);
  assert.equal(agentReport.summary.reviewRules, agentReport.rulePack.rules.length);
  assert.equal(agentReport.taskGuidance.length, agentReport.plan.tasks.length);
  assert.ok(agentReport.taskGuidance[0]?.ruleIds.length);
  assert.ok(agentReport.workflow.some((stage) => stage.id === 'challenge'));
  assert.ok(agentReport.workflow.some((stage) => stage.id === 'discover_gaps'));
  assert.equal(JSON.stringify(agentReport).includes('source tree'), true);
});

test('agent report schema embeds the rule and remediation contracts', () => {
  const schema = agentReportJsonSchema() as {
    properties?: {
      schemaVersion?: { const?: number };
      rulePack?: { properties?: { schemaVersion?: { const?: number } } };
      plan?: { properties?: { schemaVersion?: { const?: number } } };
    };
  };
  assert.equal(schema.properties?.schemaVersion?.const, 1);
  assert.equal(schema.properties?.rulePack?.properties?.schemaVersion?.const, 1);
  assert.equal(schema.properties?.plan?.properties?.schemaVersion?.const, 5);
});

test('agent report rejects guidance that references an unknown rule', () => {
  const value = buildAgentReport(sampleReport());
  value.taskGuidance[0]!.ruleIds = ['CBS-AI-UNKNOWN'];
  assert.throws(() => parseAgentReport(value), /unknown task or rule/);
});
