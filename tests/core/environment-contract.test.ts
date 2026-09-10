import test from 'node:test';
import assert from 'node:assert/strict';
import { scanEnvironmentContract } from '../../src/scanners/environment-contract.ts';
import { snapshotFromFiles, snapshotOf } from '../helpers.ts';

test('environment contract compares named source access with sanitized templates', () => {
  const result = scanEnvironmentContract(
    snapshotFromFiles({
      '.env.example': 'DATABASE_URL=\nNEXT_PUBLIC_SITE_URL=\nSTALE_NAME=\n',
      'src/server.ts': `
        const { DATABASE_URL } = process.env;
        export const missing = process.env.WEBHOOK_SECRET;
        export const feature = process.env.FEATURE_MODE;
        export const builtIn = process.env.NODE_ENV;
      `,
      'src/client.tsx': `
        'use client';
        export const site = process.env.NEXT_PUBLIC_SITE_URL;
        export const dynamic = process.env[key];
      `,
      'src/vite.ts': `export const mode = import.meta.env.MODE;`,
    }),
  );
  assert.deepEqual(result.analysis.undocumented, ['FEATURE_MODE', 'WEBHOOK_SECRET']);
  assert.deepEqual(result.analysis.unusedDeclarations, ['STALE_NAME']);
  assert.equal(result.analysis.summary.documented, 2);
  assert.equal(result.analysis.summary.platformProvided, 2);
  assert.equal(result.analysis.summary.dynamicAccesses, 1);
  assert.equal(
    result.analysis.variables.find((variable) => variable.name === 'NEXT_PUBLIC_SITE_URL')
      ?.locations[0]?.context,
    'client',
  );
  assert.deepEqual(
    result.findings.map((finding) => finding.ruleId),
    ['TW-ENV001'],
  );
  assert.match(result.findings[0]?.evidence[0]?.observation ?? '', /WEBHOOK_SECRET/);
  assert.equal(result.run.status, 'completed');
});

test('missing templates leave names unverified and create no mismatch finding', () => {
  const result = scanEnvironmentContract(
    snapshotOf('export const secret = process.env.UNDECLARED_SECRET;'),
  );
  assert.deepEqual(result.analysis.unverified, ['UNDECLARED_SECRET']);
  assert.deepEqual(result.analysis.undocumented, []);
  assert.deepEqual(result.findings, []);
  assert.ok(result.analysis.limitations.some((limitation) => limitation.includes('No captured')));
});

test('malformed source and bounded dynamic access make coverage partial', () => {
  const snapshot = snapshotFromFiles({
    '.env.template': 'KNOWN=\n',
    'src/broken.ts': 'export const broken = {',
    'src/dynamic.ts': 'export const value = process.env[name];',
  });
  const result = scanEnvironmentContract(snapshot);
  assert.equal(result.analysis.status, 'partial');
  assert.equal(result.analysis.dynamicAccesses.length, 1);
  assert.equal(result.run.status, 'partial');
});
