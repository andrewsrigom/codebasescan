import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRemediationPlan, buildRemediationResult } from '../../src/domain/remediation.ts';
import {
  parseRemediationPlan,
  parseRemediationResult,
} from '../../src/domain/remediation-schema.ts';
import { sampleReport } from '../helpers.ts';

function dependencyReport() {
  const report = sampleReport();
  const finding = report.findings[0]!;
  finding.id = 'finding-dependency';
  finding.fingerprint = 'fingerprint-dependency';
  finding.source = 'osv';
  finding.ruleId = 'GHSA-example';
  finding.category = 'dependencies';
  finding.priority = 90;
  finding.vulnerability = {
    id: 'GHSA-example',
    aliases: [],
    package: '@scope/runtime',
    version: '1.2.3',
    fixedVersions: ['1.2.5'],
    severity: [],
    relationship: 'direct',
    reachability: 'referenced',
    lockfile: 'pnpm-lock.yaml',
  };
  report.dependencies = [
    {
      name: '@scope/runtime',
      requestedVersion: '^1.2.0',
      resolvedVersion: '1.2.3',
      manifest: 'package.json',
      lockfile: 'pnpm-lock.yaml',
      relationship: 'direct',
      scope: 'runtime',
    },
  ];
  return report;
}

test('remediation plan is deterministic, bounded, and contains references instead of source', () => {
  const report = dependencyReport();
  const first = buildRemediationPlan(report);
  const second = buildRemediationPlan(report);
  assert.deepEqual(first, second);
  assert.equal(first.schemaVersion, 1);
  assert.equal(first.tasks.length, 1);
  assert.equal(first.tasks[0]?.kind, 'upgrade_dependency');
  assert.equal(first.tasks[0]?.target.fixCandidate, '1.2.5');
  assert.equal(first.tasks[0]?.constraints.execution, 'plan_only');
  assert.equal(first.tasks[0]?.constraints.network, 'requires_approval');
  assert.equal(JSON.stringify(first).includes('export const result'), false);
  assert.deepEqual(parseRemediationPlan(first), first);
});

test('unconfirmed source candidates become analysis tasks rather than automatic patches', () => {
  const plan = buildRemediationPlan(sampleReport());
  assert.equal(plan.tasks[0]?.kind, 'investigate_finding');
  assert.equal(plan.tasks[0]?.status, 'ready');
  assert.equal(plan.tasks[0]?.constraints.execution, 'plan_only');
  assert.equal(plan.tasks[0]?.constraints.network, 'denied');
});

test('remediation result separates resolved, remaining, and unexecuted checks', () => {
  const before = dependencyReport();
  const plan = buildRemediationPlan(before);
  const after = structuredClone(before);
  after.auditId = '00000000-0000-4000-8000-000000000002';
  after.snapshotDigest = 'changed-snapshot';
  after.createdAt = '2026-09-10T10:00:00.000Z';
  after.findings = [];
  const result = buildRemediationResult(plan, before, after);
  assert.equal(result.summary.resolved, 1);
  assert.equal(result.summary.snapshotChanged, true);
  assert.equal(result.taskResults[0]?.outcome, 'resolved');
  assert.equal(
    result.taskResults[0]?.verification.find((item) => item.checkId.endsWith('project_tests'))
      ?.status,
    'not_run',
  );
  assert.deepEqual(parseRemediationResult(result), result);
});

test('remediation result rejects a plan for another audit', () => {
  const before = dependencyReport();
  const plan = buildRemediationPlan(before);
  plan.audit.id = 'another-audit';
  assert.throws(() => buildRemediationResult(plan, before, before), /does not belong/);
});
