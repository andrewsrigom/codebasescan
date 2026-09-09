import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeGitleaks,
  normalizeSemgrep,
  scannerCompatibility,
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
          extra: { severity: 'ERROR', message: 'Review this sink.' },
        },
      ],
    },
    snapshotOf('eval(input)'),
  );
  assert.equal(findings[0]?.sourceSeverity, 'ERROR');
  assert.equal(findings[0]?.severity, 'high');
  assert.equal(findings[0]?.disposition, 'needs_review');
  assert.equal(findings[0]?.analysis, undefined);
});
test('scanner paths cannot escape the snapshot', () => {
  const result = normalizeSemgrep(
    { results: [{ path: '../../outside.ts', start: { line: 1 }, extra: { severity: 'ERROR' } }] },
    snapshotOf('eval(input)'),
  );
  assert.equal(result.length, 0);
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
