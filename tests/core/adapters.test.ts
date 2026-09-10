import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeGitleaks,
  normalizeSemgrep,
  scannerCompatibility,
  summarizeSemgrepErrors,
} from '../../src/scanners/external.ts';
import { snapshotOf } from '../helpers.ts';
test('Semgrep normalization preserves source severity without inventing CVSS', () => {
  const findings = normalizeSemgrep(
    {
      results: [
        {
          check_id: 'example.rule',
          path: 'src/example.ts',
          start: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Review this sink.',
            metadata: {
              category: 'authentication',
              cwe: ['CWE-347', 'not-a-cwe'],
              remediation: 'Verify the signed token before trusting claims.',
            },
          },
        },
      ],
    },
    snapshotOf('eval(input)'),
  );
  assert.equal(findings[0]?.sourceSeverity, 'ERROR');
  assert.equal(findings[0]?.severity, 'high');
  assert.equal(findings[0]?.disposition, 'needs_review');
  assert.equal(findings[0]?.analysis, undefined);
  assert.equal(findings[0]?.category, 'authentication');
  assert.deepEqual(findings[0]?.cwe, ['CWE-347']);
  assert.equal(findings[0]?.remediation, 'Verify the signed token before trusting claims.');
});
test('CodebaseScan Semgrep rule IDs stay stable when Semgrep prefixes the config path', () => {
  const findings = normalizeSemgrep(
    {
      results: [
        {
          check_id: 'home.user.codebasescan.configs.codebasescan.jwt-ignore-expiration',
          path: 'src/example.ts',
          start: { line: 1 },
          extra: { severity: 'ERROR', message: 'Review this sink.' },
        },
      ],
    },
    snapshotOf('jwt.verify(token, key, { ignoreExpiration: true });'),
  );
  assert.equal(findings[0]?.ruleId, 'codebasescan.jwt-ignore-expiration');
});
test('scanner paths cannot escape the snapshot', () => {
  const result = normalizeSemgrep(
    { results: [{ path: '../../outside.ts', start: { line: 1 }, extra: { severity: 'ERROR' } }] },
    snapshotOf('eval(input)'),
  );
  assert.equal(result.length, 0);
});

test('Semgrep diagnostics retain only safe snapshot locations', () => {
  const snapshot = snapshotOf('first line\nsecond line');
  const summary = summarizeSemgrepErrors(
    {
      errors: [
        {
          path: '/stage/source/src/example.ts',
          type: ['PartialParsing', [{ path: '/stage/source/src/example.ts', start: { line: 2 } }]],
          message: 'raw parser text must not be retained',
        },
        {
          type: [
            'PartialParsing',
            [{ path: '/stage/source/../../outside.ts', start: { line: 1 } }],
          ],
          message: 'outside path must not be retained',
        },
      ],
    },
    snapshot,
    '/stage/source',
  );

  assert.deepEqual(summary, {
    count: 2,
    locations: [{ file: 'src/example.ts', line: 2, kind: 'PartialParsing' }],
    omitted: 1,
  });
  assert.ok(!JSON.stringify(summary).includes('raw parser text'));
  assert.ok(!JSON.stringify(summary).includes('outside.ts'));
});
test('Semgrep ignores non-runtime code while Gitleaks still inspects it', () => {
  const snapshot = snapshotOf('eval(input)', 'tests/example.ts');
  snapshot.files[0]!.scope = 'test';
  const semgrep = normalizeSemgrep(
    {
      results: [
        {
          check_id: 'example.rule',
          path: 'tests/example.ts',
          start: { line: 1 },
          extra: { severity: 'ERROR', message: 'Review this sink.' },
        },
      ],
    },
    snapshot,
  );
  const gitleaks = normalizeGitleaks(
    [{ Description: 'Example secret', RuleID: 'example', File: 'tests/example.ts', StartLine: 1 }],
    snapshot,
  );
  assert.equal(semgrep.length, 0);
  assert.equal(gitleaks.length, 1);
  assert.equal(gitleaks[0]?.evidence[0]?.scope, 'test');
  assert.equal(gitleaks[0]?.secret?.classification, 'fixture_candidate');
  assert.equal(gitleaks[0]?.confidence, 'low');
  assert.equal(gitleaks[0]?.severity, 'medium');
});
test('malformed scanner schemas fail explicitly', () => {
  assert.throws(() => normalizeSemgrep({ results: 'not-an-array' }, snapshotOf('')));
  assert.throws(() => normalizeGitleaks({}, snapshotOf('')));
});
test('Gitleaks normalization discards raw secrets and matched lines', () => {
  const findings = normalizeGitleaks(
    [
      {
        Description: 'Example secret',
        RuleID: 'example',
        File: 'src/example.ts',
        StartLine: 1,
        Secret: 'sensitive-fixture-value',
        Match: 'sensitive-fixture-value',
      },
    ],
    snapshotOf('const token = "sensitive-fixture-value";'),
  );
  const output = JSON.stringify(findings);
  assert.ok(!output.includes('sensitive-fixture-value'));
  assert.equal(findings[0]?.evidence[0]?.excerpt, '[Source excerpt withheld for secret findings]');
  assert.equal(findings[0]?.secret?.classification, 'probable');
  assert.equal(findings[0]?.confidence, 'medium');
});

test('Gitleaks history normalization keeps only safe metadata', () => {
  const findings = normalizeGitleaks(
    [
      {
        Description: 'Historical token',
        RuleID: 'history-fixture',
        File: 'removed/credentials.ts',
        StartLine: 7,
        Commit: 'a'.repeat(40),
        Secret: 'historical-secret-value',
        Match: 'historical-secret-value',
      },
    ],
    snapshotOf('export const safe = true;'),
    '/project',
    true,
  );
  assert.equal(findings[0]?.secret?.classification, 'historical');
  assert.equal(findings[0]?.secret?.commit, 'a'.repeat(40));
  assert.equal(findings[0]?.evidence[0]?.kind, 'history');
  assert.equal(findings[0]?.evidence[0]?.file, 'removed/credentials.ts');
  assert.ok(!JSON.stringify(findings).includes('historical-secret-value'));
});

test('external scanner versions distinguish tested, unknown, and untested compatibility', () => {
  assert.equal(scannerCompatibility('semgrep', '1.176.1').status, 'tested');
  assert.equal(scannerCompatibility('gitleaks', '8.30.1').status, 'tested');
  assert.equal(scannerCompatibility('semgrep').status, 'unknown');
  const future = scannerCompatibility('gitleaks', '9.0.0');
  assert.equal(future.status, 'untested');
  assert.match(future.detail, /coverage is partial/);
});

test('out-of-bounds scanner locations cannot fabricate source evidence', () => {
  const source = snapshotOf('eval(input)');
  for (const line of [0, -1, 999, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.equal(
      normalizeSemgrep(
        {
          results: [
            {
              check_id: 'bad-location',
              path: 'src/example.ts',
              start: { line },
              extra: { severity: 'ERROR' },
            },
          ],
        },
        source,
      ).length,
      0,
    );
    assert.equal(
      normalizeGitleaks([{ File: 'src/example.ts', StartLine: line }], source).length,
      0,
    );
  }
});
