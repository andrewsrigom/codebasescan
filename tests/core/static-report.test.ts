import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { writeStaticReport } from '../../src/reporting/static-report.ts';
import { parseRemediationPlan } from '../../src/domain/remediation-schema.ts';
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
      'remediation-plan.json',
      'codex-bundle.json',
      'report.md',
      'report.sarif',
      'sbom.cdx.json',
    ],
  );
  const html = await readFile(path.join(result.directory, 'index.html'), 'utf8');
  assert.ok(html.includes("default-src 'none'"));
  assert.ok(html.includes('href="remediation-plan.json"'));
  const plan = parseRemediationPlan(
    JSON.parse(await readFile(path.join(result.directory, 'remediation-plan.json'), 'utf8')),
  );
  assert.equal(plan.audit.id, report.auditId);
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
