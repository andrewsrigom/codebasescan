import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { writeStaticReport } from '../../src/reporting/static-report.ts';
import { parseRemediationPlan } from '../../src/domain/remediation-schema.ts';
import { parseRemediationResult } from '../../src/domain/remediation-schema.ts';
import { buildRemediationPlan } from '../../src/domain/remediation.ts';
import { remediationPlanArtifactDigest } from '../../src/domain/verification-ledger.ts';
import { parseRuleQualityReport } from '../../src/domain/rule-quality-schema.ts';
import { parseRunManifest } from '../../src/domain/run-manifest-schema.ts';
import { parsePolicyResult } from '../../src/domain/policy-schema.ts';
import { parseAgentReport } from '../../src/domain/agent-report-schema.ts';
import { parseAgentReviewRulePack } from '../../src/domain/agent-rules.ts';
import {
  sampleApiContract,
  sampleDatabaseContract,
  sampleEnvironmentContract,
  sampleFeatureFlags,
  sampleReport,
  sampleRiskCorrelation,
  sampleTestEvidence,
  sampleWebhookContract,
} from '../helpers.ts';

test('static report writes a self-contained report directory', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-static-report-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const report = sampleReport();
  report.riskCorrelation = sampleRiskCorrelation(report.findings[0]!.id);
  report.environmentContract = sampleEnvironmentContract();
  report.testEvidence = sampleTestEvidence();
  report.apiContract = sampleApiContract();
  report.databaseContract = sampleDatabaseContract();
  report.webhookContract = sampleWebhookContract();
  report.featureFlags = sampleFeatureFlags();
  const result = await writeStaticReport(report, temporary);
  assert.equal(result.directory, temporary);
  assert.deepEqual(
    result.manifest.files.map((file) => file.path),
    [
      'index.html',
      'run-manifest.json',
      'audit-report.json',
      'risk-paths.json',
      'environment-contract.json',
      'test-evidence.json',
      'api-contract.json',
      'database-contract.json',
      'webhook-contract.json',
      'feature-flags.json',
      'agent-plan.json',
      'agent-report.json',
      'agent-report.schema.json',
      'agent-rules.json',
      'agent-rules.schema.json',
      'remediation-plan.json',
      'agent-plan.schema.json',
      'run-manifest.schema.json',
      'policy-result.json',
      'policy-result.schema.json',
      'rule-quality.json',
      'rule-quality.schema.json',
      'review-ledger.schema.json',
      'calibration-ledger.schema.json',
      'calibration-report.schema.json',
      'suppression-ledger.schema.json',
      'verification-ledger.schema.json',
      'codex-bundle.json',
      'report.md',
      'report.sarif',
      'sbom.cdx.json',
    ],
  );
  const html = await readFile(path.join(result.directory, 'index.html'), 'utf8');
  assert.ok(html.includes("default-src 'none'"));
  assert.ok(html.includes('href="risk-paths.json"'));
  assert.ok(html.includes('href="environment-contract.json"'));
  assert.ok(html.includes('href="test-evidence.json"'));
  assert.ok(html.includes('href="api-contract.json"'));
  assert.ok(html.includes('href="database-contract.json"'));
  assert.ok(html.includes('href="webhook-contract.json"'));
  assert.ok(html.includes('href="feature-flags.json"'));
  assert.ok(html.includes('href="run-manifest.json"'));
  assert.ok(!html.includes('href="manifest.json"'));
  assert.ok(html.includes('href="run-manifest.schema.json"'));
  assert.ok(html.includes('href="policy-result.json"'));
  assert.ok(html.includes('href="policy-result.schema.json"'));
  assert.ok(html.includes('href="suppression-ledger.schema.json"'));
  assert.ok(html.includes('DETERMINISTIC POLICY'));
  assert.ok(html.includes('Policy result'));
  assert.ok(html.includes('href="agent-plan.json"'));
  assert.ok(html.includes('href="agent-report.json"'));
  assert.ok(html.includes('href="agent-report.schema.json"'));
  assert.ok(html.includes('href="agent-rules.json"'));
  assert.ok(html.includes('href="agent-rules.schema.json"'));
  assert.ok(html.includes('href="agent-plan.schema.json"'));
  assert.ok(html.includes('href="rule-quality.json"'));
  assert.ok(html.includes('href="review-ledger.schema.json"'));
  assert.ok(html.includes('href="calibration-ledger.schema.json"'));
  assert.ok(html.includes('href="calibration-report.schema.json"'));
  assert.ok(html.includes('REMEDIATION QUEUE'));
  assert.ok(html.includes('Prioritized work items'));
  assert.ok(html.includes('How to read this report'));
  assert.ok(html.includes('What we found'));
  assert.ok(html.includes('Why it matters'));
  assert.ok(html.includes('Where to look'));
  assert.ok(html.includes('How to verify manually'));
  assert.ok(html.includes('Confidence and limitations'));
  assert.ok(html.includes('Show captured source'));
  assert.ok(html.includes('What to do next'));
  assert.ok(html.includes('Consider it resolved when'));
  assert.ok(!html.includes('<code>rem-'));
  assert.ok(!html.includes('Components:'));
  assert.ok(html.includes('CAUSE-ORIENTED REVIEW'));
  assert.ok(html.includes('Likely root causes'));
  assert.ok(html.includes('RULE TRANSPARENCY'));
  assert.ok(html.includes('Applied rule quality'));
  const agentPlan = await readFile(path.join(result.directory, 'agent-plan.json'), 'utf8');
  const riskPaths = JSON.parse(
    await readFile(path.join(result.directory, 'risk-paths.json'), 'utf8'),
  ) as { summary: { paths: number } };
  assert.equal(riskPaths.summary.paths, 1);
  const environmentContract = JSON.parse(
    await readFile(path.join(result.directory, 'environment-contract.json'), 'utf8'),
  ) as { summary: { undocumented: number } };
  assert.equal(environmentContract.summary.undocumented, 1);
  const testEvidence = JSON.parse(
    await readFile(path.join(result.directory, 'test-evidence.json'), 'utf8'),
  ) as { withoutRelatedTests: number };
  assert.equal(testEvidence.withoutRelatedTests, 1);
  const apiContract = JSON.parse(
    await readFile(path.join(result.directory, 'api-contract.json'), 'utf8'),
  ) as { summary: { sourceOnly: number } };
  assert.equal(apiContract.summary.sourceOnly, 1);
  const databaseContract = JSON.parse(
    await readFile(path.join(result.directory, 'database-contract.json'), 'utf8'),
  ) as { summary: { gapCandidates: number } };
  assert.equal(databaseContract.summary.gapCandidates, 1);
  const webhookContract = JSON.parse(
    await readFile(path.join(result.directory, 'webhook-contract.json'), 'utf8'),
  ) as { summary: { matchedEvents: number } };
  assert.equal(webhookContract.summary.matchedEvents, 1);
  const featureFlags = JSON.parse(
    await readFile(path.join(result.directory, 'feature-flags.json'), 'utf8'),
  ) as { summary: { matchedFlags: number } };
  assert.equal(featureFlags.summary.matchedFlags, 1);
  assert.equal(
    agentPlan,
    await readFile(path.join(result.directory, 'remediation-plan.json'), 'utf8'),
  );
  const plan = parseRemediationPlan(JSON.parse(agentPlan));
  assert.equal(plan.audit.id, report.auditId);
  const agentReport = parseAgentReport(
    JSON.parse(await readFile(path.join(result.directory, 'agent-report.json'), 'utf8')),
  );
  assert.equal(agentReport.audit.id, report.auditId);
  assert.equal(agentReport.plan.audit.id, report.auditId);
  const agentRules = parseAgentReviewRulePack(
    JSON.parse(await readFile(path.join(result.directory, 'agent-rules.json'), 'utf8')),
  );
  assert.ok(agentRules.rules.length >= 10);
  const agentReportSchema = JSON.parse(
    await readFile(path.join(result.directory, 'agent-report.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(agentReportSchema.properties?.schemaVersion?.const, 1);
  const agentRulesSchema = JSON.parse(
    await readFile(path.join(result.directory, 'agent-rules.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(agentRulesSchema.properties?.schemaVersion?.const, 1);
  const schema = JSON.parse(
    await readFile(path.join(result.directory, 'agent-plan.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(schema.properties?.schemaVersion?.const, 5);
  const runManifest = parseRunManifest(
    JSON.parse(await readFile(path.join(result.directory, 'run-manifest.json'), 'utf8')),
  );
  assert.equal(runManifest.audit.id, report.auditId);
  assert.equal(runManifest.audit.reportSchemaVersion, report.schemaVersion);
  assert.equal(runManifest.modes.selectionAvailable, false);
  assert.equal(runManifest.execution.scannerStatus.completed, 1);
  assert.equal(runManifest.execution.scannerDurationMs, 1);
  assert.equal(runManifest.scope.truncated, false);
  assert.ok(runManifest.outputs.some((output) => output.path === 'audit-report.json'));
  assert.ok(runManifest.outputs.every((output) => /^[a-f0-9]{64}$/.test(output.sha256)));
  const runManifestSchema = JSON.parse(
    await readFile(path.join(result.directory, 'run-manifest.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(runManifestSchema.properties?.schemaVersion?.const, 2);
  const policyResult = parsePolicyResult(
    JSON.parse(await readFile(path.join(result.directory, 'policy-result.json'), 'utf8')),
  );
  assert.equal(policyResult.profile, 'advisory');
  assert.equal(policyResult.exitCode, 0);
  const policyResultSchema = JSON.parse(
    await readFile(path.join(result.directory, 'policy-result.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(policyResultSchema.properties?.schemaVersion?.const, 1);
  const suppressionLedgerSchema = JSON.parse(
    await readFile(path.join(result.directory, 'suppression-ledger.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(suppressionLedgerSchema.properties?.schemaVersion?.const, 1);
  const markdown = await readFile(path.join(result.directory, 'report.md'), 'utf8');
  assert.ok(markdown.includes('## Policy result'));
  assert.ok(markdown.includes('Profile: advisory. Decision: advisory. Exit code: 0.'));
  const ruleQuality = parseRuleQualityReport(
    JSON.parse(await readFile(path.join(result.directory, 'rule-quality.json'), 'utf8')),
  );
  assert.equal(ruleQuality.auditId, report.auditId);
  assert.equal(ruleQuality.summary.appliedRules, 1);
  const investigationBundle = JSON.parse(
    await readFile(path.join(result.directory, 'codex-bundle.json'), 'utf8'),
  ) as {
    schemaVersion: number;
    environmentContract: { summary: { undocumented: number } };
    apiContract: { summary: { sourceOnly: number } };
    databaseContract: { summary: { gapCandidates: number } };
    webhookContract: { summary: { matchedEvents: number } };
    featureFlags: { summary: { matchedFlags: number } };
  };
  assert.equal(investigationBundle.schemaVersion, 4);
  assert.equal(investigationBundle.environmentContract.summary.undocumented, 1);
  assert.equal(investigationBundle.apiContract.summary.sourceOnly, 1);
  assert.equal(investigationBundle.webhookContract.summary.matchedEvents, 1);
  assert.equal(investigationBundle.featureFlags.summary.matchedFlags, 1);
  assert.equal(investigationBundle.databaseContract.summary.gapCandidates, 1);
  const ruleQualitySchema = JSON.parse(
    await readFile(path.join(result.directory, 'rule-quality.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(ruleQualitySchema.properties?.schemaVersion?.const, 3);
  const calibrationLedgerSchema = JSON.parse(
    await readFile(path.join(result.directory, 'calibration-ledger.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(calibrationLedgerSchema.properties?.schemaVersion?.const, 1);
  const calibrationReportSchema = JSON.parse(
    await readFile(path.join(result.directory, 'calibration-report.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(calibrationReportSchema.properties?.schemaVersion?.const, 1);
  const manifest = JSON.parse(
    await readFile(path.join(result.directory, 'manifest.json'), 'utf8'),
  ) as { kind: string; files: { sha256: string }[] };
  assert.equal(manifest.kind, 'codebasescan-static-report');
  assert.match(manifest.files[0]?.sha256 ?? '', /^[a-f0-9]{64}$/);
  assert.equal(result.rootEntrypoint, path.join(temporary, 'index.html'));
  const rootHtml = await readFile(result.rootEntrypoint, 'utf8');
  assert.ok(rootHtml.includes('How to read this report'));
  assert.ok(!rootHtml.includes('<script'));
});

test('static report root is updated with the newest audit', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-static-report-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const older = sampleReport();
  older.riskCorrelation = sampleRiskCorrelation(older.findings[0]!.id);
  const newer = {
    ...sampleReport(),
    auditId: '00000000-0000-4000-8000-000000000099',
    createdAt: '2026-09-08T14:00:00.000Z',
  };
  await writeStaticReport(older, temporary);
  const result = await writeStaticReport(newer, temporary);
  assert.equal(result.manifest.auditId, newer.auditId);
  assert.equal(
    await readFile(path.join(temporary, 'audit-report.json'), 'utf8'),
    `${JSON.stringify(newer, null, 2)}\n`,
  );
  await assert.rejects(readFile(path.join(temporary, 'risk-paths.json'), 'utf8'), {
    code: 'ENOENT',
  });
});

test('static report refuses to overwrite an unmanaged directory', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-static-parent-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const destination = path.join(temporary, 'existing-site');
  await mkdir(destination);
  await writeFile(path.join(destination, 'index.html'), 'user content');
  await assert.rejects(
    () => writeStaticReport(sampleReport(), destination),
    /not managed by CodebaseScan/,
  );
});

test('static report records remediation progress when a baseline is supplied', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-static-report-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const baseline = sampleReport();
  const current: typeof baseline = {
    ...structuredClone(baseline),
    auditId: '00000000-0000-4000-8000-000000000002',
    createdAt: '2026-09-08T13:00:00.000Z',
    snapshotDigest: 'a'.repeat(64),
    findings: [],
  };
  const verificationLedger = {
    schemaVersion: 1 as const,
    kind: 'codebasescan-verification-ledger' as const,
    createdAt: '2026-09-08T12:59:00.000Z',
    project: {
      name: baseline.projectName,
      before: { auditId: baseline.auditId, snapshotDigest: baseline.snapshotDigest },
      after: { auditId: current.auditId, snapshotDigest: current.snapshotDigest },
    },
    planDigest: remediationPlanArtifactDigest(buildRemediationPlan(baseline)),
    executions: [],
  };
  const result = await writeStaticReport(current, temporary, { baseline, verificationLedger });
  assert.ok(result.manifest.files.some((file) => file.path === 'remediation-result.json'));
  assert.ok(result.manifest.files.some((file) => file.path === 'remediation-result.schema.json'));
  assert.ok(result.manifest.files.some((file) => file.path === 'verification-ledger.json'));
  const remediation = parseRemediationResult(
    JSON.parse(await readFile(path.join(result.directory, 'remediation-result.json'), 'utf8')),
  );
  assert.equal(remediation.before.auditId, baseline.auditId);
  assert.equal(remediation.after.auditId, current.auditId);
  assert.equal(remediation.summary.resolved, 1);
  assert.equal(remediation.externalVerification?.executionsReceived, 0);
  const html = await readFile(path.join(result.directory, 'index.html'), 'utf8');
  assert.ok(html.includes('BEFORE / AFTER'));
  assert.ok(html.includes('href="remediation-result.json"'));
  assert.ok(html.includes('href="verification-ledger.json"'));
});
