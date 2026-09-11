import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { buildAuditPipeline } from '../../src/engine/audit-pipeline.ts';
import { AuditStore } from '../../src/server/store.ts';
import { configuration } from '../../src/server/config.ts';
import { executeAudit } from '../../src/engine/run.ts';
import { disableTelemetry } from '../../src/security/privacy.ts';

disableTelemetry();

async function temporaryConfig(context: test.TestContext, prefix: string) {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix));
  context.after(() => rm(directory, { recursive: true, force: true }));
  return {
    ...configuration(),
    dataDirectory: directory,
    temporaryDirectory: path.join(directory, 'temporary'),
    scannerCacheDirectory: path.join(directory, 'scanner-cache'),
    semgrep: false,
    gitleaks: false,
    osv: false,
  };
}

test('deterministic pipeline collects every scanner before producing the report', async (context) => {
  const store = new AuditStore(':memory:');
  context.after(() => store.close());
  const root = path.resolve('fixtures/review-worthy-saas');
  const project = store.registerProject('Pipeline fixture', root);
  const audit = store.enqueue(project.id);
  store.claim(audit.id);
  const pipeline = buildAuditPipeline({
    root,
    projectName: project.name,
    config: await temporaryConfig(context, 'codebasescan-pipeline-'),
    store,
  });

  await pipeline.invoke({ auditId: audit.id });

  const report = store.audit(audit.id).report;
  assert.equal(report?.findings.length, 8);
  assert.equal(report?.scanners.length, 27);
  assert.equal(report?.schemaVersion, 17);
  assert.equal(report?.aiMode, 'disabled');
  assert.equal(report?.publication, 'draft');
  for (const scanner of [
    'project-profile',
    'ast-security',
    'saas-security',
    'react-security',
    'next-security',
    'accessibility-static',
    'privacy-static',
    'reliability-static',
    'environment-contract',
  ])
    assert.ok(
      report?.scanners.some((run) => run.id === scanner),
      scanner,
    );
  assert.equal(report?.projectProfile?.status, 'complete');
  assert.ok(report?.environmentContract);
  assert.ok(report?.testEvidence);
  assert.ok(report?.webhookContract);
  assert.ok(report?.featureFlags);
  assert.ok(report?.riskCorrelation);
  assert.ok(report?.mechanicalAnalysis?.architecture);
  assert.ok(report?.mechanicalAnalysis?.duplication);
  assert.ok(report?.supplyChainAnalysis);
  assert.ok(report?.codeQualityAnalysis);
  assert.equal(report?.checklist?.packId, 'codebasescan-web-application');
  assert.ok(report?.findings.every((finding) => finding.analysis === undefined));
});

test('focused modes keep disabled capabilities visible', async (context) => {
  const store = new AuditStore(':memory:');
  context.after(() => store.close());
  const root = path.resolve('fixtures/hardened-saas');
  const project = store.registerProject('Focused fixture', root);
  const audit = store.enqueue(project.id, { modes: ['accessibility-static'] });
  store.claim(audit.id);
  const pipeline = buildAuditPipeline({
    root,
    projectName: project.name,
    config: await temporaryConfig(context, 'codebasescan-focused-'),
    store,
    modes: audit.options.modes,
  });

  await pipeline.invoke({ auditId: audit.id });

  const report = store.audit(audit.id).report;
  assert.equal(
    report?.auditModes?.find((mode) => mode.id === 'accessibility-static')?.enabled,
    true,
  );
  assert.equal(report?.auditModes?.find((mode) => mode.id === 'security')?.enabled, false);
  assert.equal(report?.coverage?.find((item) => item.id === 'builtin')?.status, 'DISABLED');
  assert.equal(
    report?.coverage?.find((item) => item.id === 'accessibility-static')?.status,
    'COMPLETE',
  );
  assert.equal(report?.mechanicalAnalysis, undefined);
});

test('identical focused audits reuse deterministic scanner results', async (context) => {
  const store = new AuditStore(':memory:');
  context.after(() => store.close());
  const root = path.resolve('fixtures/hardened-saas');
  const project = store.registerProject('Cache fixture', root);
  const config = await temporaryConfig(context, 'codebasescan-cache-pipeline-');

  const run = async () => {
    const audit = store.enqueue(project.id, { modes: ['accessibility-static'] });
    store.claim(audit.id);
    await buildAuditPipeline({
      root,
      projectName: project.name,
      config,
      store,
      modes: audit.options.modes,
    }).invoke({ auditId: audit.id });
    const report = store.audit(audit.id).report;
    store.transition(audit.id, 'completed');
    return report;
  };

  const first = await run();
  const second = await run();
  for (const scannerId of ['project-profile', 'accessibility-static']) {
    assert.equal(
      first?.scanners.find((scanner) => scanner.id === scannerId)?.cache?.status,
      'miss',
    );
    assert.equal(
      second?.scanners.find((scanner) => scanner.id === scannerId)?.cache?.status,
      'hit',
    );
  }
  assert.deepEqual(
    second?.findings.map((finding) => finding.fingerprint),
    first?.findings.map((finding) => finding.fingerprint),
  );
});

test('execution rejects incompatible workflow versions', async (context) => {
  const store = new AuditStore(':memory:');
  context.after(() => store.close());
  const project = store.registerProject(
    'Compatibility fixture',
    path.resolve('fixtures/hardened-saas'),
  );
  const audit = store.enqueue(project.id);
  store.claim(audit.id);
  store.db
    .prepare('UPDATE audits SET workflow_version = ? WHERE id = ?')
    .run('codebasescan-audit-legacy', audit.id);
  const config = await temporaryConfig(context, 'codebasescan-version-');

  await assert.rejects(() => executeAudit(store, audit.id, config), /workflow .* incompatible/);
});

test('default audits make no network calls', async (context) => {
  const store = new AuditStore(':memory:');
  context.after(() => store.close());
  const project = store.registerProject('Offline fixture', path.resolve('fixtures/hardened-saas'));
  const audit = store.enqueue(project.id);
  store.claim(audit.id);
  let calls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    throw new Error('Network must not be used.');
  };
  context.after(() => {
    globalThis.fetch = originalFetch;
  });

  await executeAudit(store, audit.id, await temporaryConfig(context, 'codebasescan-offline-'));

  assert.equal(calls, 0);
  assert.equal(store.audit(audit.id).status, 'completed');
});
