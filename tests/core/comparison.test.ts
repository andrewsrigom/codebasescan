import test from 'node:test';
import assert from 'node:assert/strict';
import { compareReports } from '../../src/domain/comparison.ts';
import { sampleReport } from '../helpers.ts';
import { baselineCiGate, ciGate } from '../../src/domain/ci.ts';

test('report comparison separates new, resolved, unchanged, and severity changes', () => {
  const base = sampleReport();
  base.auditId = '00000000-0000-4000-8000-000000000001';
  const unchanged = { ...base.findings[0]!, severity: 'critical' as const };
  const added = {
    ...base.findings[0]!,
    id: 'new-id',
    fingerprint: 'new-fingerprint',
    ruleId: 'TW-NEW',
  };
  const current = sampleReport();
  current.auditId = '00000000-0000-4000-8000-000000000002';
  current.findings = [unchanged, added];
  const comparison = compareReports(base, current);
  assert.equal(comparison.schemaVersion, 3);
  assert.equal(comparison.historyReports, 0);
  assert.equal(comparison.newFindings.length, 1);
  assert.equal(comparison.resolvedFindings.length, 0);
  assert.equal(comparison.unchangedFindings.length, 1);
  assert.deepEqual(comparison.severityChanges[0], {
    finding: {
      id: unchanged.id,
      fingerprint: unchanged.fingerprint,
      ruleId: unchanged.ruleId,
      title: unchanged.title,
      severity: 'critical',
    },
    before: 'high',
    after: 'critical',
  });
  assert.deepEqual(comparison.reappearedFindings, []);
  assert.equal(comparison.components[0]?.name, 'Unassigned');

  current.findings = [added];
  assert.equal(compareReports(base, current).resolvedFindings.length, 1);
});

test('dependency lifecycle ignores lockfile line churn for the same advisory instance', () => {
  const base = sampleReport();
  const finding = base.findings[0]!;
  finding.source = 'osv';
  finding.ruleId = 'GHSA-example';
  finding.vulnerability = {
    id: 'GHSA-example',
    aliases: [],
    package: 'postcss',
    version: '8.5.8',
    fixedVersions: ['8.5.23'],
    severity: [],
    relationship: 'transitive',
    reachability: 'referenced',
    lockfile: 'pnpm-lock.yaml',
  };
  const current = structuredClone(base);
  current.auditId = '00000000-0000-4000-8000-000000000002';
  current.findings[0]!.id = 'moved-finding';
  current.findings[0]!.fingerprint = 'moved-lockfile-line-fingerprint';

  const comparison = compareReports(base, current);
  assert.equal(comparison.newFindings.length, 0);
  assert.equal(comparison.resolvedFindings.length, 0);
  assert.equal(comparison.unchangedFindings.length, 1);
});

test('comparison attributes lifecycle to components and identifies reappearing fingerprints', () => {
  const historical = sampleReport();
  historical.auditId = '00000000-0000-4000-8000-000000000000';
  const base = sampleReport();
  base.auditId = '00000000-0000-4000-8000-000000000001';
  base.findings = [];
  const current = sampleReport();
  current.auditId = '00000000-0000-4000-8000-000000000002';
  current.projectProfile = {
    schemaVersion: 1,
    status: 'complete',
    languages: ['typescript'],
    frameworks: [],
    components: [
      {
        id: 'component-api',
        name: 'api',
        root: 'src',
        manifest: 'package.json',
        kind: 'package',
        sourceFiles: 1,
      },
    ],
    componentEdges: [],
    entrypoints: [],
    symbols: [],
    imports: [],
    calls: [],
    facts: [],
    filesAnalyzed: 1,
    nodesAnalyzed: 1,
    issues: [],
    truncated: false,
  };
  const comparison = compareReports(base, current, [historical, historical]);
  assert.equal(comparison.historyReports, 1);
  assert.deepEqual(
    comparison.reappearedFindings.map((finding) => finding.fingerprint),
    [current.findings[0]!.fingerprint],
  );
  assert.deepEqual(comparison.newFindings[0]?.componentIds, ['component-api']);
  assert.deepEqual(comparison.components, [
    {
      componentId: 'component-api',
      name: 'api',
      newFindings: 1,
      resolvedFindings: 0,
      unchangedFindings: 0,
      reappearedFindings: 1,
      severityChanges: 0,
      dispositionChanges: 0,
    },
  ]);
});

test('comparison records disposition and component ownership changes separately', () => {
  const base = sampleReport();
  const current = structuredClone(base);
  current.auditId = '00000000-0000-4000-8000-000000000002';
  current.findings[0]!.disposition = 'confirmed';
  base.projectProfile = {
    schemaVersion: 1,
    status: 'complete',
    languages: ['typescript'],
    frameworks: [],
    components: [
      {
        id: 'old-component',
        name: 'old',
        root: 'src',
        manifest: 'package.json',
        kind: 'package',
        sourceFiles: 1,
      },
    ],
    componentEdges: [],
    entrypoints: [],
    symbols: [],
    imports: [],
    calls: [],
    facts: [],
    filesAnalyzed: 1,
    nodesAnalyzed: 1,
    issues: [],
    truncated: false,
  };
  current.projectProfile = structuredClone(base.projectProfile);
  current.projectProfile.components![0]!.id = 'new-component';
  current.projectProfile.components![0]!.name = 'new';
  const comparison = compareReports(base, current);
  assert.deepEqual(comparison.dispositionChanges[0], {
    finding: {
      id: current.findings[0]!.id,
      fingerprint: current.findings[0]!.fingerprint,
      ruleId: current.findings[0]!.ruleId,
      title: current.findings[0]!.title,
      severity: current.findings[0]!.severity,
      componentIds: ['new-component'],
    },
    before: 'needs_review',
    after: 'confirmed',
  });
  assert.deepEqual(comparison.componentChanges[0]?.before, ['old-component']);
  assert.deepEqual(comparison.componentChanges[0]?.after, ['new-component']);
});

test('CI severity gates use meaningful exit codes', () => {
  const report = sampleReport();
  assert.deepEqual(ciGate(report, 'critical'), { exitCode: 0, gatedFindings: 0 });
  assert.deepEqual(ciGate(report, 'high'), { exitCode: 1, gatedFindings: 1 });
  report.findings[0]!.disposition = 'accepted_risk';
  assert.deepEqual(ciGate(report, 'high'), { exitCode: 0, gatedFindings: 0 });
  report.findings[0]!.disposition = 'fixed';
  assert.deepEqual(ciGate(report, 'high'), { exitCode: 0, gatedFindings: 0 });
  report.findings[0]!.disposition = 'needs_review';
  report.findings[0]!.suppression = {
    reason: 'Project exception with reviewed rationale.',
    createdAt: '2026-09-09T00:00:00.000Z',
  };
  assert.deepEqual(ciGate(report, 'high'), { exitCode: 0, gatedFindings: 0 });
});

test('baseline CI gate counts only new findings at the selected severity', () => {
  const base = sampleReport();
  const current = sampleReport();
  current.findings = [
    ...base.findings,
    {
      ...base.findings[0]!,
      id: 'new-medium-id',
      fingerprint: 'new-medium-fingerprint',
      severity: 'medium',
    },
  ];
  const comparison = compareReports(base, current);
  assert.deepEqual(baselineCiGate(comparison, 'high'), { exitCode: 0, gatedFindings: 0 });
  assert.deepEqual(baselineCiGate(comparison, 'medium'), { exitCode: 1, gatedFindings: 1 });
  current.findings.at(-1)!.suppression = {
    reason: 'Project exception with reviewed rationale.',
    createdAt: '2026-09-09T00:00:00.000Z',
  };
  assert.deepEqual(baselineCiGate(compareReports(base, current), 'medium'), {
    exitCode: 0,
    gatedFindings: 0,
  });
});
