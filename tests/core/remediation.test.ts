import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildRemediationPlan,
  buildRemediationResult,
  buildRemediationTaskBundle,
} from '../../src/domain/remediation.ts';
import {
  parseRemediationPlan,
  parseRemediationResult,
  remediationPlanJsonSchema,
} from '../../src/domain/remediation-schema.ts';
import { sampleReport, sampleRiskCorrelation } from '../helpers.ts';

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
  assert.equal(first.schemaVersion, 4);
  assert.equal(first.tasks.length, 1);
  assert.equal(first.tasks[0]?.kind, 'upgrade_dependency');
  assert.equal(first.tasks[0]?.target.fixCandidate, '1.2.5');
  assert.equal(first.tasks[0]?.constraints.execution, 'plan_only');
  assert.equal(first.tasks[0]?.constraints.network, 'requires_approval');
  assert.match(first.tasks[0]?.rootCause.id ?? '', /^cause-[a-f0-9]{16}$/);
  assert.equal(first.tasks[0]?.priorityFactors.length, 4);
  assert.deepEqual(first.tasks[0]?.verificationCommands[0]?.argv, [
    'traceward',
    'audit',
    '.',
    '--format',
    'json',
  ]);
  assert.equal(first.tasks[0]?.verificationCommands[0]?.requiresApproval, true);
  assert.equal(first.tasks[0]?.autoFixable, true);
  assert.equal(first.summary.rootCauseGroups, 1);
  assert.equal(JSON.stringify(first).includes('export const result'), false);
  assert.deepEqual(parseRemediationPlan(first), first);
});

test('agent plan JSON Schema describes the current required contract', () => {
  const schema = remediationPlanJsonSchema() as {
    properties?: { schemaVersion?: { const?: number }; tasks?: unknown };
    required?: string[];
  };
  assert.equal(schema.properties?.schemaVersion?.const, 4);
  assert.ok(schema.required?.includes('tasks'));
});

test('unconfirmed source candidates become analysis tasks rather than automatic patches', () => {
  const report = sampleReport();
  report.riskCorrelation = sampleRiskCorrelation(report.findings[0]!.id);
  report.projectProfile = {
    schemaVersion: 1,
    status: 'complete',
    languages: ['typescript'],
    frameworks: [],
    entrypoints: [],
    symbols: [],
    imports: [],
    calls: [],
    facts: [],
    filesAnalyzed: 1,
    nodesAnalyzed: 1,
    issues: [],
    truncated: false,
    saasSemantics: {
      schemaVersion: 1,
      sources: ['traceward.config.json'],
      vocabulary: {
        tenantKeys: [],
        ownerKeys: [],
        roleKeys: [],
        billingKeys: [],
        tokenKeys: [],
      },
      helpers: {
        authentication: [],
        authorization: [],
        validation: [],
        resourceScope: [],
        rateLimit: [],
        idempotency: [],
        csrf: [],
        auditLog: [],
      },
      expectedUnauthenticatedRoutes: [],
      verification: {
        packageManager: 'pnpm',
        testScripts: ['test:unit'],
        buildScripts: ['build'],
      },
    },
  };
  const plan = buildRemediationPlan(report);
  assert.equal(plan.tasks[0]?.kind, 'investigate_finding');
  assert.equal(plan.tasks[0]?.status, 'ready');
  assert.equal(plan.tasks[0]?.constraints.execution, 'plan_only');
  assert.equal(plan.tasks[0]?.constraints.network, 'denied');
  assert.equal(plan.tasks[0]?.autoFixable, false);
  assert.equal(plan.tasks[0]?.requiresHuman, true);
  assert.deepEqual(plan.tasks[0]?.riskPathIds, ['risk-path-1']);
  assert.deepEqual(
    plan.tasks[0]?.verificationCommands.map((command) => command.argv),
    [
      ['pnpm', 'run', 'test:unit'],
      ['pnpm', 'run', 'build'],
      ['traceward', 'audit', '.', '--format', 'json'],
    ],
  );
});

test('same-rule findings in one file become one task without losing references', () => {
  const report = sampleReport();
  report.findings.push({
    ...structuredClone(report.findings[0]!),
    id: 'second-finding',
    fingerprint: 'second-fingerprint',
  });
  const plan = buildRemediationPlan(report);
  assert.equal(plan.tasks.length, 1);
  assert.deepEqual(
    plan.tasks[0]?.findings.map((finding) => finding.id),
    [report.findings[0]?.id, 'second-finding'],
  );
  assert.equal(plan.summary.rootCauseGroups, 1);
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

test('task bundle contains only the selected task and its bounded evidence', () => {
  const report = dependencyReport();
  const plan = buildRemediationPlan(report);
  const unrelated = {
    ...structuredClone(report.findings[0]!),
    id: 'unrelated-finding',
    fingerprint: 'unrelated-fingerprint',
    ruleId: 'unrelated-rule',
  };
  unrelated.vulnerability!.package = 'other-package';
  report.findings.push(unrelated);
  const bundle = buildRemediationTaskBundle(report, plan.tasks[0]!.id);
  assert.equal(bundle.kind, 'traceward-remediation-task-bundle');
  assert.equal(bundle.task.id, plan.tasks[0]!.id);
  assert.deepEqual(
    bundle.findings.map((finding) => finding.id),
    ['finding-dependency'],
  );
  assert.equal(JSON.stringify(bundle).includes('unrelated-finding'), false);
  assert.equal('root' in bundle.audit, false);
});

test('task bundle includes only source paths related to the selected findings', () => {
  const report = sampleReport();
  report.riskCorrelation = sampleRiskCorrelation(report.findings[0]!.id);
  report.riskCorrelation.paths.push({
    ...structuredClone(report.riskCorrelation.paths[0]!),
    id: 'unrelated-risk-path',
    findingIds: ['another-finding'],
  });
  const plan = buildRemediationPlan(report);
  const bundle = buildRemediationTaskBundle(report, plan.tasks[0]!.id);
  assert.equal(bundle.schemaVersion, 2);
  assert.deepEqual(bundle.task.riskPathIds, ['risk-path-1']);
  assert.deepEqual(
    bundle.riskPaths.map((path) => path.id),
    ['risk-path-1'],
  );
  assert.equal(JSON.stringify(bundle).includes('unrelated-risk-path'), false);
});

test('task bundle rejects an unknown task id', () => {
  assert.throws(
    () => buildRemediationTaskBundle(sampleReport(), 'rem-does-not-exist'),
    /not found/,
  );
});
