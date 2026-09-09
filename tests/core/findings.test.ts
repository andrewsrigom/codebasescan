import test from 'node:test';
import assert from 'node:assert/strict';
import { scanPatterns } from '../../src/scanners/builtin.ts';
import { inventory } from '../../src/scanners/inventory.ts';
import { mergeFindings } from '../../src/domain/findings.ts';
import { snapshotOf } from '../helpers.ts';
const cases = [
  ['TW-001', 'database.$queryRawUnsafe(query)'],
  ['TW-002', '<div dangerouslySetInnerHTML={{ __html: value }} />'],
  ['TW-003', 'eval(input)'],
  ['TW-004', 'database.project.findUnique({ where: { id } })'],
  ['TW-005', 'process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY'],
  ['TW-006', `({ 'Access-Control-Allow-Origin': '*' })`],
  ['TW-007', 'createAgent({ tools: [readUser, deleteUser] })'],
] as const;
for (const [rule, content] of cases) {
  test(`detects ${rule} without automatically confirming it`, () => {
    const findings = scanPatterns(snapshotOf(content));
    assert.ok(findings.some((finding) => finding.ruleId === rule));
    assert.ok(findings.every((finding) => finding.disposition === 'needs_review'));
    assert.ok(findings.every((finding) => finding.analysis === undefined));
  });
}
test('retains stable IDs within an identical snapshot', () => {
  const first = scanPatterns(snapshotOf('eval(input)'));
  const second = scanPatterns(snapshotOf('eval(input)'));
  assert.equal(first[0]?.id, second[0]?.id);
  assert.equal(mergeFindings(first, second).length, 1);
});
test('does not flag a paired tenant-scoped alternative', () => {
  assert.equal(
    scanPatterns(
      snapshotOf('database.project.findFirst({ where: { id, tenantId: session.tenantId } })'),
    ).length,
    0,
  );
});
test('generic ID lookups remain medium-severity review hotspots', () => {
  const finding = scanPatterns(snapshotOf('database.project.findUnique({ where: { id } })')).find(
    (candidate) => candidate.ruleId === 'TW-004',
  );
  assert.equal(finding?.severity, 'medium');
  assert.match(finding?.description ?? '', /review hotspot, not evidence/i);
});
test('documents a deliberate comment false positive', () => {
  const findings = scanPatterns(snapshotOf('// Do not use eval(input) anymore.'));
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.disposition, 'needs_review');
});
test('caps findings to prevent unbounded output', () => {
  assert.equal(scanPatterns(snapshotOf('eval(input);\n'.repeat(500))).length, 300);
});
test('package inventory preserves requested ranges rather than inventing resolved versions', () => {
  const dependencies = inventory(
    snapshotOf(
      '{"dependencies":{"next":"^16.3.4"},"devDependencies":{"typescript":"~5.9.3"}}',
      'package.json',
    ),
  );
  assert.equal(dependencies[0]?.requestedVersion, '^16.3.4');
  assert.equal(dependencies[0]?.scope, 'runtime');
  assert.equal(dependencies[1]?.scope, 'development');
});
test('invalid package JSON does not crash the inventory', () => {
  assert.deepEqual(inventory(snapshotOf('{', 'package.json')), []);
});
