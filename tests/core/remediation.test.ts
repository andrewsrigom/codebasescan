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
import {
  remediationPlanArtifactDigest,
  type VerificationLedger,
} from '../../src/domain/verification-ledger.ts';
import {
  parseVerificationLedger,
  verificationLedgerJsonSchema,
} from '../../src/domain/verification-ledger-schema.ts';
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
  assert.equal(first.schemaVersion, 5);
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
  assert.equal(schema.properties?.schemaVersion?.const, 5);
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
    components: [],
    componentEdges: [],
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

test('remediation result keeps a source finding remaining after line-only movement', () => {
  const before = sampleReport();
  const plan = buildRemediationPlan(before);
  const after = structuredClone(before);
  after.auditId = '00000000-0000-4000-8000-000000000002';
  after.snapshotDigest = 'changed-snapshot';
  after.createdAt = '2026-09-10T10:00:00.000Z';
  after.findings[0]!.id = 'moved-finding';
  after.findings[0]!.fingerprint = 'moved-source-line-fingerprint';
  after.findings[0]!.evidence[0]!.startLine += 28;
  after.findings[0]!.evidence[0]!.endLine += 28;
  after.findings[0]!.evidence[0]!.focusLine = (after.findings[0]!.evidence[0]!.focusLine ?? 1) + 28;

  const result = buildRemediationResult(plan, before, after);
  assert.equal(result.summary.resolved, 0);
  assert.equal(result.summary.remaining, 1);
  assert.equal(result.summary.newFindings, 0);
  assert.equal(result.taskResults[0]?.outcome, 'remaining');
});

test('remediation result applies exact external test and build evidence', () => {
  const before = dependencyReport();
  const plan = buildRemediationPlan(before);
  const task = plan.tasks[0]!;
  task.verificationCommands.unshift(
    {
      id: `${task.id}:project-test:test`,
      kind: 'project_test',
      argv: ['pnpm', 'run', 'test'],
      workingDirectory: 'project_root',
      timeoutSeconds: 900,
      network: 'denied',
      requiresApproval: true,
      source: 'project_context',
    },
    {
      id: `${task.id}:project-build:build`,
      kind: 'project_build',
      argv: ['pnpm', 'run', 'build'],
      workingDirectory: 'project_root',
      timeoutSeconds: 1_800,
      network: 'denied',
      requiresApproval: true,
      source: 'project_context',
    },
  );
  const after = structuredClone(before);
  after.auditId = '00000000-0000-4000-8000-000000000002';
  after.snapshotDigest = 'a'.repeat(64);
  after.createdAt = '2026-09-10T10:00:00.000Z';
  after.findings = [];
  const ledger: VerificationLedger = {
    schemaVersion: 1,
    kind: 'traceward-verification-ledger',
    createdAt: '2026-09-10T09:59:00.000Z',
    project: {
      name: before.projectName,
      before: { auditId: before.auditId, snapshotDigest: before.snapshotDigest },
      after: { auditId: after.auditId, snapshotDigest: after.snapshotDigest },
    },
    planDigest: remediationPlanArtifactDigest(plan),
    executions: [
      {
        id: 'execution-1111111111111111',
        kind: 'project_test',
        argv: ['pnpm', 'run', 'test'],
        workingDirectory: 'project_root',
        startedAt: '2026-09-10T09:00:00.000Z',
        durationMs: 12_000,
        exitCode: 0,
        outputSha256: 'b'.repeat(64),
        outputBytes: 4_096,
        outputTruncated: false,
        executor: 'test-agent',
        network: 'denied',
      },
      {
        id: 'execution-2222222222222222',
        kind: 'project_build',
        argv: ['pnpm', 'run', 'build'],
        workingDirectory: 'project_root',
        startedAt: '2026-09-10T09:01:00.000Z',
        durationMs: 24_000,
        exitCode: 0,
        outputSha256: 'c'.repeat(64),
        outputBytes: 8_192,
        outputTruncated: true,
        executor: 'test-agent',
        network: 'denied',
      },
      {
        id: 'execution-3333333333333333',
        kind: 'project_test',
        argv: ['pnpm', 'run', 'lint'],
        workingDirectory: 'project_root',
        startedAt: '2026-09-10T09:02:00.000Z',
        durationMs: 1_000,
        exitCode: 0,
        outputSha256: 'd'.repeat(64),
        outputBytes: 1_024,
        outputTruncated: false,
        executor: 'test-agent',
        network: 'denied',
      },
    ],
  };

  assert.deepEqual(parseVerificationLedger(ledger), ledger);
  const result = buildRemediationResult(plan, before, after, ledger);
  assert.equal(result.schemaVersion, 3);
  assert.equal(result.taskResults[0]?.outcome, 'resolved');
  assert.equal(
    result.taskResults[0]?.verification.find((item) => item.checkId.endsWith('project_tests'))
      ?.status,
    'passed',
  );
  assert.equal(
    result.taskResults[0]?.verification.find((item) => item.checkId.endsWith('project_build'))
      ?.status,
    'passed',
  );
  assert.equal(result.externalVerification?.executionsReceived, 3);
  assert.equal(result.externalVerification?.executionsApplied, 2);
  assert.deepEqual(result.externalVerification?.unmatchedExecutionIds, [
    'execution-3333333333333333',
  ]);
  assert.deepEqual(parseRemediationResult(result), result);

  const failedLedger = structuredClone(ledger);
  failedLedger.executions[0]!.exitCode = 1;
  const failed = buildRemediationResult(plan, before, after, failedLedger);
  assert.equal(failed.taskResults[0]?.outcome, 'partial');
  assert.equal(
    failed.taskResults[0]?.verification.find((item) => item.checkId.endsWith('project_tests'))
      ?.status,
    'failed',
  );

  const staleLedger = structuredClone(ledger);
  staleLedger.project.after.snapshotDigest = 'e'.repeat(64);
  assert.throws(
    () => buildRemediationResult(plan, before, after, staleLedger),
    /does not match the after audit/,
  );
});

test('verification ledger schema is strict and versioned', () => {
  const schema = verificationLedgerJsonSchema() as {
    properties?: { schemaVersion?: { const?: number }; executions?: unknown };
    required?: string[];
  };
  assert.equal(schema.properties?.schemaVersion?.const, 1);
  assert.ok(schema.required?.includes('executions'));
  assert.throws(() =>
    parseVerificationLedger({
      schemaVersion: 1,
      kind: 'traceward-verification-ledger',
      createdAt: '2026-09-10T09:59:00.000Z',
      project: {
        name: 'example',
        before: { auditId: 'before', snapshotDigest: 'a'.repeat(64) },
        after: { auditId: 'after', snapshotDigest: 'b'.repeat(64) },
      },
      planDigest: 'c'.repeat(64),
      executions: [
        {
          id: 'execution-1111111111111111',
          kind: 'project_test',
          argv: ['pnpm', 'run', 'test'],
          workingDirectory: 'project_root',
          startedAt: '2026-09-10T09:00:00.000Z',
          durationMs: 10,
          exitCode: 0,
          outputSha256: 'd'.repeat(64),
          outputBytes: 10,
          outputTruncated: false,
          executor: 'test-agent',
          network: 'denied',
          output: 'must not be retained',
        },
      ],
    }),
  );
});

test('remediation keeps an advisory open when only its lockfile-line fingerprint changes', () => {
  const before = dependencyReport();
  const plan = buildRemediationPlan(before);
  const after = structuredClone(before);
  after.auditId = '00000000-0000-4000-8000-000000000002';
  after.snapshotDigest = 'changed-snapshot';
  after.findings[0]!.id = 'moved-finding';
  after.findings[0]!.fingerprint = 'moved-lockfile-line-fingerprint';

  const result = buildRemediationResult(plan, before, after);
  assert.equal(result.schemaVersion, 3);
  assert.equal(result.summary.resolved, 0);
  assert.equal(result.summary.remaining, 1);
  assert.equal(result.summary.newFindings, 0);
  assert.equal(result.taskResults[0]?.outcome, 'remaining');
  assert.equal(
    result.taskResults[0]?.verification.find((item) => item.checkId.endsWith('finding_absent'))
      ?.status,
    'failed',
  );
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
  assert.equal(bundle.schemaVersion, 3);
  assert.deepEqual(bundle.task.riskPathIds, ['risk-path-1']);
  assert.deepEqual(
    bundle.riskPaths.map((path) => path.id),
    ['risk-path-1'],
  );
  assert.equal(JSON.stringify(bundle).includes('unrelated-risk-path'), false);
});

test('tasks and bundles carry bounded component and test-evidence context', () => {
  const report = sampleReport();
  const finding = report.findings[0]!;
  finding.evidence[0]!.file = 'apps/web/src/app/api/example/route.ts';
  report.projectProfile = {
    schemaVersion: 1,
    status: 'complete',
    languages: ['typescript'],
    frameworks: [],
    components: [
      {
        id: 'component-web',
        name: 'web',
        root: 'apps/web',
        manifest: 'apps/web/package.json',
        kind: 'package',
        sourceFiles: 2,
      },
      {
        id: 'component-worker',
        name: 'worker',
        root: 'apps/worker',
        manifest: 'apps/worker/package.json',
        kind: 'package',
        sourceFiles: 1,
      },
    ],
    componentEdges: [
      {
        id: 'edge-web-worker',
        fromComponentId: 'component-web',
        toComponentId: 'component-worker',
        imports: 1,
        importIds: ['import-1'],
        truncated: false,
      },
    ],
    entrypoints: [
      {
        id: 'entrypoint-1',
        kind: 'next-route',
        file: 'apps/web/src/app/api/example/route.ts',
        line: 1,
        name: '/api/example',
        methods: ['POST'],
        dynamicParameters: [],
        symbolIds: [],
        componentId: 'component-web',
      },
    ],
    symbols: [],
    imports: [],
    calls: [],
    facts: [],
    filesAnalyzed: 2,
    nodesAnalyzed: 2,
    issues: [],
    truncated: false,
  };
  report.testEvidence = {
    schemaVersion: 1,
    version: '1.0.0',
    status: 'complete',
    testFiles: 1,
    criticalFiles: 1,
    withRelatedTests: 1,
    withoutRelatedTests: 0,
    targets: [
      {
        file: 'apps/web/src/app/api/example/route.ts',
        componentId: 'component-web',
        entrypointIds: ['entrypoint-1'],
        sensitiveFactIds: [],
        sensitiveFactKinds: [],
        status: 'observed',
        relatedTests: [
          {
            file: 'apps/web/src/app/api/example/route.test.ts',
            relation: 'direct-import',
            depth: 1,
          },
        ],
        truncated: false,
      },
    ],
    parseFailures: 0,
    unresolvedImports: 0,
    truncated: false,
    limitations: ['Static relationship only.'],
  };
  const plan = buildRemediationPlan(report);
  const task = plan.tasks[0]!;
  assert.deepEqual(task.componentIds, ['component-web']);
  assert.deepEqual(task.testEvidenceFiles, ['apps/web/src/app/api/example/route.ts']);
  const bundle = buildRemediationTaskBundle(report, task.id);
  assert.deepEqual(
    bundle.projectContext?.components.map((component) => component.id),
    ['component-web', 'component-worker'],
  );
  assert.deepEqual(
    bundle.projectContext?.componentEdges.map((edge) => edge.id),
    ['edge-web-worker'],
  );
  assert.equal(bundle.projectContext?.testEvidence?.targets.length, 1);
  assert.equal(bundle.projectContext?.testEvidence?.targets[0]?.relatedTests.length, 1);
});

test('task bundle rejects an unknown task id', () => {
  assert.throws(
    () => buildRemediationTaskBundle(sampleReport(), 'rem-does-not-exist'),
    /not found/,
  );
});
