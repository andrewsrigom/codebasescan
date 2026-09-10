import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { writeStaticReport } from '../../src/reporting/static-report.ts';
import { parseRemediationPlan } from '../../src/domain/remediation-schema.ts';
import { parseRemediationResult } from '../../src/domain/remediation-schema.ts';
import { parseRuleQualityReport } from '../../src/domain/rule-quality-schema.ts';
import { sampleReport } from '../helpers.ts';

test('static report writes a self-contained versioned artifact directory', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-static-report-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const report = sampleReport();
  const result = await writeStaticReport(report, temporary);
  assert.equal(result.directory, path.join(temporary, report.auditId));
  assert.deepEqual(
    result.manifest.files.map((file) => file.path),
    [
      'index.html',
      'audit-report.json',
      'agent-plan.json',
      'remediation-plan.json',
      'agent-plan.schema.json',
      'rule-quality.json',
      'rule-quality.schema.json',
      'review-ledger.schema.json',
      'codex-bundle.json',
      'report.md',
      'report.sarif',
      'sbom.cdx.json',
    ],
  );
  const html = await readFile(path.join(result.directory, 'index.html'), 'utf8');
  assert.ok(html.includes("default-src 'none'"));
  assert.ok(html.includes('href="agent-plan.json"'));
  assert.ok(html.includes('href="agent-plan.schema.json"'));
  assert.ok(html.includes('href="rule-quality.json"'));
  assert.ok(html.includes('href="review-ledger.schema.json"'));
  assert.ok(html.includes('REMEDIATION QUEUE'));
  assert.ok(html.includes('Prioritized work items'));
  assert.ok(html.includes('CAUSE-ORIENTED REVIEW'));
  assert.ok(html.includes('Likely root causes'));
  assert.ok(html.includes('RULE TRANSPARENCY'));
  assert.ok(html.includes('Applied rule quality'));
  const agentPlan = await readFile(path.join(result.directory, 'agent-plan.json'), 'utf8');
  assert.equal(
    agentPlan,
    await readFile(path.join(result.directory, 'remediation-plan.json'), 'utf8'),
  );
  const plan = parseRemediationPlan(JSON.parse(agentPlan));
  assert.equal(plan.audit.id, report.auditId);
  const schema = JSON.parse(
    await readFile(path.join(result.directory, 'agent-plan.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(schema.properties?.schemaVersion?.const, 3);
  const ruleQuality = parseRuleQualityReport(
    JSON.parse(await readFile(path.join(result.directory, 'rule-quality.json'), 'utf8')),
  );
  assert.equal(ruleQuality.auditId, report.auditId);
  assert.equal(ruleQuality.summary.appliedRules, 1);
  const ruleQualitySchema = JSON.parse(
    await readFile(path.join(result.directory, 'rule-quality.schema.json'), 'utf8'),
  ) as { properties?: { schemaVersion?: { const?: number } } };
  assert.equal(ruleQualitySchema.properties?.schemaVersion?.const, 1);
  const manifest = JSON.parse(
    await readFile(path.join(result.directory, 'manifest.json'), 'utf8'),
  ) as { kind: string; files: { sha256: string }[] };
  assert.equal(manifest.kind, 'traceward-static-report');
  assert.match(manifest.files[0]?.sha256 ?? '', /^[a-f0-9]{64}$/);
});

test('static report refuses to overwrite an existing audit directory', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-static-report-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const report = sampleReport();
  await writeStaticReport(report, temporary);
  await assert.rejects(() => writeStaticReport(report, temporary), /already exists/);
});

test('static report records remediation progress when a baseline is supplied', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-static-report-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const baseline = sampleReport();
  const current: typeof baseline = {
    ...structuredClone(baseline),
    auditId: '00000000-0000-4000-8000-000000000002',
    createdAt: '2026-09-08T13:00:00.000Z',
    snapshotDigest: 'a'.repeat(64),
    findings: [],
  };
  const result = await writeStaticReport(current, temporary, { baseline });
  assert.ok(result.manifest.files.some((file) => file.path === 'remediation-result.json'));
  const remediation = parseRemediationResult(
    JSON.parse(await readFile(path.join(result.directory, 'remediation-result.json'), 'utf8')),
  );
  assert.equal(remediation.before.auditId, baseline.auditId);
  assert.equal(remediation.after.auditId, current.auditId);
  assert.equal(remediation.summary.resolved, 1);
  const html = await readFile(path.join(result.directory, 'index.html'), 'utf8');
  assert.ok(html.includes('BEFORE / AFTER'));
  assert.ok(html.includes('href="remediation-result.json"'));
});
