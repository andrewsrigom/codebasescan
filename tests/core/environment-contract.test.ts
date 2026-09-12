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

test('environment contract keeps optional defaults and writes out of the finding queue', () => {
  const result = scanEnvironmentContract(
    snapshotFromFiles({
      '.env.example': 'DOCUMENTED_SECRET=\n# OPTIONAL_DOCUMENTED_SECRET=\n',
      'src/config.ts': `
        process.env.RESOLVED_SECRET = resolveSecret();
        const optionalSecret = process.env.OPTIONAL_SECRET ?? '';
        const alternateSecret = process.env.PRIMARY_SECRET || process.env.SECONDARY_SECRET;
        const flag = process.env.AUTH_DISABLE_RATE_LIMIT === 'true';
        const retries = readPositiveInt(process.env.AUTH_RETRIES, 3);
        const optionalRedisUrl = process.env.OPTIONAL_REDIS_URL?.trim();
        const legacySecret = trimToUndefined(process.env.LEGACY_AUTH_SECRET);
        const selectedSecret = documentedSecret ? documentedSecret : legacySecret ? legacySecret : null;
        const trustedOrigins = [
          process.env.AUTH_TRUSTED_ORIGINS,
          process.env.LEGACY_AUTH_TRUSTED_ORIGINS,
        ].filter(Boolean);
        for (const candidate of [
          process.env.AUTH_BASE_URL,
          process.env.NEXT_PUBLIC_SITE_URL,
        ]) normalizeUrl(candidate);
        const siteUrlCandidates = [
          process.env.AUTH_SITE_URL,
          process.env.LEGACY_AUTH_SITE_URL,
          'http://localhost:3000',
        ];
        for (const candidate of siteUrlCandidates) normalizeUrl(candidate);
        function resolveSiteUrl() {
          if (process.env.AUTH_FALLBACK_URL) return process.env.AUTH_FALLBACK_URL;
          if (process.env.LEGACY_AUTH_FALLBACK_URL) return process.env.LEGACY_AUTH_FALLBACK_URL;
          return 'http://localhost:3000';
        }
        const requiredSecret = process.env.REQUIRED_SECRET;
      `,
    }),
  );

  assert.ok(!result.analysis.variables.some((variable) => variable.name === 'RESOLVED_SECRET'));
  assert.deepEqual(
    result.findings.map((finding) => finding.evidence[0]?.observation),
    [
      'Environment name REQUIRED_SECRET is referenced but absent from captured environment templates. No value was read.',
    ],
  );
  assert.ok(result.analysis.undocumented.includes('OPTIONAL_SECRET'));
  assert.ok(result.analysis.undocumented.includes('AUTH_RETRIES'));
  assert.ok(result.analysis.undocumented.includes('OPTIONAL_REDIS_URL'));
  assert.ok(result.analysis.undocumented.includes('LEGACY_AUTH_SECRET'));
  assert.ok(result.analysis.undocumented.includes('AUTH_TRUSTED_ORIGINS'));
  assert.ok(result.analysis.undocumented.includes('AUTH_BASE_URL'));
  assert.ok(result.analysis.undocumented.includes('AUTH_SITE_URL'));
  assert.ok(result.analysis.undocumented.includes('AUTH_FALLBACK_URL'));
  assert.ok(!result.analysis.undocumented.includes('OPTIONAL_DOCUMENTED_SECRET'));
  assert.ok(result.analysis.unusedDeclarations.includes('OPTIONAL_DOCUMENTED_SECRET'));
});

test('a guarded environment read remains required when failure is explicit', () => {
  const result = scanEnvironmentContract(
    snapshotFromFiles({
      '.env.example': 'DOCUMENTED=\n',
      'src/config.ts': `
        export function requireSecret() {
          if (process.env.REQUIRED_GUARDED_SECRET) {
            return process.env.REQUIRED_GUARDED_SECRET;
          }
          throw new Error('Missing required secret');
        }
      `,
    }),
  );
  assert.ok(
    result.findings.some((finding) =>
      finding.evidence[0]?.observation.includes('REQUIRED_GUARDED_SECRET'),
    ),
  );
});
