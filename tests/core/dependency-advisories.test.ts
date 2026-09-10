import test from 'node:test';
import assert from 'node:assert/strict';
import type { Finding } from '../../src/domain/types.ts';
import { groupDependencyAdvisories } from '../../src/domain/dependency-advisories.ts';

function advisory(input: {
  id: string;
  package: string;
  version: string;
  fixedVersions: string[];
  severity?: Finding['severity'];
  relationship?: NonNullable<Finding['vulnerability']>['relationship'];
  reachability?: NonNullable<Finding['vulnerability']>['reachability'];
}): Finding {
  return {
    id: input.id,
    fingerprint: input.id,
    source: 'osv',
    ruleId: input.id,
    title: input.id,
    category: 'dependencies',
    severity: input.severity ?? 'high',
    sourceSeverity: 'HIGH',
    description: 'Known advisory.',
    remediation: 'Upgrade after compatibility review.',
    cwe: [],
    evidence: [],
    disposition: 'needs_review',
    priority: 80,
    vulnerability: {
      id: input.id,
      aliases: [],
      package: input.package,
      version: input.version,
      fixedVersions: input.fixedVersions,
      severity: [],
      relationship: input.relationship ?? 'transitive',
      reachability: input.reachability ?? 'unknown',
      lockfile: 'package-lock.json',
    },
  };
}

test('dependency advisories group by package and version with bounded fix claims', () => {
  const findings = [
    advisory({
      id: 'ADV-1',
      package: 'framework',
      version: '16.2.2',
      fixedVersions: ['15.5.24', '16.2.11'],
      severity: 'critical',
      relationship: 'direct',
      reachability: 'referenced',
    }),
    advisory({
      id: 'ADV-2',
      package: 'framework',
      version: '16.2.2',
      fixedVersions: ['15.5.16'],
      relationship: 'direct',
      reachability: 'referenced',
    }),
    advisory({
      id: 'ADV-3',
      package: 'parser',
      version: '7.5.4',
      fixedVersions: ['7.5.6'],
    }),
  ];
  const groups = groupDependencyAdvisories(findings, [
    {
      name: 'framework',
      requestedVersion: '^16.2.0',
      resolvedVersion: '16.2.2',
      manifest: 'package.json',
      scope: 'runtime',
      relationship: 'direct',
    },
  ]);
  assert.equal(groups.length, 2);
  assert.equal(groups[0]?.package, 'framework');
  assert.equal(groups[0]?.advisoryCount, 2);
  assert.equal(groups[0]?.relationship, 'direct');
  assert.equal(groups[0]?.reachability, 'referenced');
  assert.equal(groups[0]?.versionPlans[0]?.fixCandidate, '16.2.11');
  assert.equal(groups[0]?.versionPlans[0]?.fixCoverage, 1);
  assert.deepEqual(groups[0]?.versionPlans[0]?.scopes, ['runtime']);
  assert.match(groups[0]?.versionPlans[0]?.action ?? '', /1\/2 advisories/);
  assert.match(groups[0]?.versionPlans[0]?.action ?? '', /branch or vendor review/);
});

test('dependency advisory plans do not guess from non-semver or major-only fixes', () => {
  const groups = groupDependencyAdvisories([
    advisory({
      id: 'ADV-1',
      package: 'parser',
      version: '7.5.4',
      fixedVersions: ['8.0.1'],
    }),
    advisory({
      id: 'ADV-2',
      package: 'commit-package',
      version: 'git+abc',
      fixedVersions: ['1.0.0'],
    }),
  ]);
  assert.equal(groups[0]?.versionPlans[0]?.fixCandidate, undefined);
  assert.equal(groups[1]?.versionPlans[0]?.fixCandidate, undefined);
  assert.ok(groups.every((group) => group.versionPlans[0]?.fixCoverage === 0));
});
