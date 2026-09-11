import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { startReportServer, loadReportPackage } from '../../src/reporting/report-server.ts';
import { writeStaticReport } from '../../src/reporting/static-report.ts';
import { sampleReport } from '../helpers.ts';

test('report package loader resolves the newest audit from a report root', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-report-server-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const older = sampleReport();
  const newer = {
    ...sampleReport(),
    auditId: '00000000-0000-4000-8000-000000000099',
    createdAt: '2026-09-08T14:00:00.000Z',
  };
  await writeStaticReport(older, temporary);
  await writeStaticReport(newer, temporary);

  const loaded = await loadReportPackage(temporary);
  assert.equal(loaded.report.auditId, newer.auditId);
  assert.equal(loaded.directory, path.join(temporary, newer.auditId));

  const running = await startReportServer(temporary, 0);
  context.after(() => running.close());
  const history = await fetch(running.url);
  assert.equal(history.status, 200);
  const historyHtml = await history.text();
  assert.match(historyHtml, /Audit history/);
  assert.match(historyHtml, new RegExp(`href="\\./${newer.auditId}/index\\.html"`));
  const olderPage = await fetch(new URL(`${older.auditId}/index.html`, running.url));
  assert.equal(olderPage.status, 200);
  assert.match(await olderPage.text(), /Review summary/);
});

test('report server exposes only verified manifest artifacts on loopback', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-report-server-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const report = sampleReport();
  const output = await writeStaticReport(report, temporary);
  const running = await startReportServer(output.directory, 0);
  context.after(() => running.close());

  assert.match(running.url, /^http:\/\/127\.0\.0\.1:\d+\/$/);
  const page = await fetch(running.url);
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy') ?? '', /default-src 'none'/);
  assert.match(await page.text(), /Review summary/);

  const audit = await fetch(new URL('audit-report.json', running.url));
  assert.equal(audit.status, 200);
  assert.equal(((await audit.json()) as { auditId: string }).auditId, report.auditId);

  const hidden = await fetch(new URL('manifest.json', running.url));
  assert.equal(hidden.status, 404);
  const method = await fetch(running.url, { method: 'POST' });
  assert.equal(method.status, 405);
});

test('report package loader rejects modified artifacts', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-report-server-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const output = await writeStaticReport(sampleReport(), temporary);
  const auditFile = path.join(output.directory, 'audit-report.json');
  const original = await readFile(auditFile, 'utf8');
  await writeFile(auditFile, `${original} `, { mode: 0o600 });

  await assert.rejects(() => loadReportPackage(output.directory), /integrity validation/);
});
