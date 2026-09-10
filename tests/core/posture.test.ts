import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { captureSnapshot } from '../../src/security/paths.ts';
import { scanPosture } from '../../src/scanners/posture.ts';
import { snapshotOf } from '../helpers.ts';

const expectedRules = [
  'TW-P001',
  'TW-P002',
  'TW-P003',
  'TW-P004',
  'TW-P005',
  'TW-P006',
  'TW-P007',
  'TW-P008',
  'TW-P009',
  'TW-P010',
  'TW-P011',
  'TW-P012',
  'TW-P013',
] as const;

test('posture fixture exercises every rule as an unresolved review candidate', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/posture-vulnerable'));
  const findings = scanPosture(snapshot);
  const rules = new Set(findings.map((finding) => finding.ruleId));
  for (const rule of expectedRules) assert.ok(rules.has(rule), `${rule} was not detected`);
  assert.ok(findings.every((finding) => finding.source === 'posture'));
  assert.ok(findings.every((finding) => finding.disposition === 'needs_review'));
  assert.ok(
    findings
      .filter((finding) => ['TW-P010', 'TW-P011'].includes(finding.ruleId))
      .every(
        (finding) => finding.evidence[0]?.excerpt === '[Sensitive configuration value withheld]',
      ),
  );
});

test('safe posture fixture is not reported by the posture scanner', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/posture-safe'));
  assert.deepEqual(scanPosture(snapshot), []);
});

test('intentionally client-readable preference cookies are not treated as sessions', () => {
  const snapshot = snapshotOf(
    "response.cookies.set('theme', 'dark', { sameSite: 'lax' });",
    'src/app/api/preferences/route.ts',
  );
  assert.equal(
    scanPosture(snapshot).some((finding) => finding.ruleId === 'TW-P003'),
    false,
  );
});

test('header absence is not blindly reported without an in-scope framework config', () => {
  const snapshot = snapshotOf('{"dependencies":{"next":"16.3.4"}}', 'package.json');
  assert.equal(
    scanPosture(snapshot).some((finding) => finding.ruleId === 'TW-P001'),
    false,
  );
});
