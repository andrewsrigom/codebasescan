import test from 'node:test';
import assert from 'node:assert/strict';
import {
  escapeHtml,
  escapeMarkdown,
  toCycloneDx,
  toHtml,
  toInvestigationBundle,
  toMarkdown,
  toSarif,
} from '../../src/domain/reports.ts';
import { sampleReport } from '../helpers.ts';
import { buildCoverage } from '../../src/domain/coverage.ts';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { buildSecurityChecklist } from '../../src/domain/checklist.ts';
import { snapshotOf } from '../helpers.ts';
test('HTML export escapes source and titles rather than executing them', () => {
  const report = sampleReport();
  report.projectName = '<script>alert(1)</script>';
  report.findings[0]!.evidence[0]!.excerpt = '<img src=x onerror=alert(1)>';
  const output = toHtml(report);
  assert.ok(!output.includes('<script>'));
  assert.ok(!output.includes('<img src=x'));
  assert.ok(output.includes('&lt;script&gt;'));
  assert.ok(output.includes("default-src 'none'"));
  assert.ok(output.includes('Review summary'));
  assert.ok(output.includes('Review priorities'));
  assert.ok(output.includes('Need human review'));
  assert.ok(output.includes('id="finding-1"'));
});
test('SARIF export retains unresolved status and valid local locations', () => {
  const result = toSarif(sampleReport()) as {
    version: string;
    runs: {
      results: {
        properties: {
          disposition: string;
        };
      }[];
    }[];
  };
  assert.equal(result.version, '2.1.0');
  assert.equal(result.runs[0]?.results[0]?.properties.disposition, 'needs_review');
});
test('CycloneDX export preserves dependency scope and direct relationships', () => {
  const report = sampleReport();
  report.dependencies = [
    {
      name: '@scope/runtime',
      requestedVersion: '^1.0.0',
      resolvedVersion: '1.2.3',
      manifest: 'package.json',
      lockfile: 'package-lock.json',
      relationship: 'direct',
      scope: 'runtime',
    },
    {
      name: 'test-helper',
      requestedVersion: '2.0.0',
      resolvedVersion: '2.0.0',
      manifest: 'package.json',
      lockfile: 'package-lock.json',
      relationship: 'transitive',
      scope: 'development',
    },
  ];
  const result = toCycloneDx(report) as {
    bomFormat: string;
    specVersion: string;
    components: { name: string; scope: string; purl: string }[];
    dependencies: { dependsOn: string[] }[];
  };
  assert.equal(result.bomFormat, 'CycloneDX');
  assert.equal(result.specVersion, '1.6');
  assert.equal(result.components[0]?.scope, 'required');
  assert.match(result.components[0]?.purl ?? '', /^pkg:npm\/%40scope\/runtime@1\.2\.3$/);
  assert.equal(result.dependencies[0]?.dependsOn.length, 1);
});
test('Markdown includes scope and limitations', () => {
  const report = sampleReport();
  report.projectProfile = profileProject(
    snapshotOf('export function handler() { return Response.json({ ok: true }); }'),
  ).profile;
  report.checklist = buildSecurityChecklist({
    projectProfile: report.projectProfile,
    findings: report.findings,
    scanners: report.scanners,
    dependencies: report.dependencies,
  });
  report.checklist.controls[0]!.review = {
    decision: 'verified_external',
    note: 'Gateway enforcement was inspected in the authorized environment.',
    at: '2026-09-09T12:00:00.000Z',
  };
  report.coverage = buildCoverage(report.scanners, report.findings, report.aiMode);
  const output = toMarkdown(report);
  assert.ok(output.includes('not a security certification'));
  assert.ok(output.includes('## Coverage'));
  assert.ok(output.includes('Capability summary'));
  assert.ok(output.includes('## Project structure'));
  assert.ok(output.includes('## Security checklist'));
  assert.ok(output.includes('Human assessment: verified external'));
  assert.ok(toHtml(report).includes('Human assessment: verified external'));
  assert.ok(output.includes('NOT SUPPORTED'));
  assert.ok(output.includes('## Limitations'));
});
test('Markdown escapes raw HTML and link syntax from untrusted report text', () => {
  const report = sampleReport();
  report.projectName = '<script>alert(1)</script> [run](javascript:alert(1))';
  report.findings[0]!.review = {
    decision: 'needs_review',
    note: '<img src=x onerror=alert(1)>',
    at: '2026-09-08T12:00:00.000Z',
  };
  const output = toMarkdown(report);
  assert.ok(!output.includes('<script>'));
  assert.ok(!output.includes('<img'));
  assert.ok(!output.includes('[run](javascript:'));
  assert.ok(output.includes('&lt;script&gt;'));
});
test('standard HTML metacharacters are escaped', () => {
  assert.equal(escapeHtml('<>&"'), '&lt;&gt;&amp;&quot;');
  assert.equal(escapeMarkdown('<tag> [label](target)'), '&lt;tag&gt; \\[label\\]\\(target\\)');
});
test('investigation bundle is bounded, evidence-led, and ready for manual AI review', () => {
  const report = sampleReport();
  report.projectProfile = profileProject(
    snapshotOf('export function handler() { return Response.json({ ok: true }); }'),
  ).profile;
  report.checklist = buildSecurityChecklist({
    projectProfile: report.projectProfile,
    findings: report.findings,
    scanners: report.scanners,
    dependencies: [],
  });
  const bundle = toInvestigationBundle(report) as {
    kind: string;
    policy: string[];
    findings: { id: string; evidence: { id: string }[] }[];
    projectMap: { entrypoints: unknown[]; securityFacts: unknown[]; callEdges: unknown[] };
  };
  assert.equal(bundle.kind, 'traceward-investigation-bundle');
  assert.ok(bundle.policy.some((item) => item.includes('untrusted evidence')));
  assert.equal(bundle.findings[0]?.id, report.findings[0]?.id);
  assert.equal(bundle.findings[0]?.evidence[0]?.id, report.findings[0]?.evidence[0]?.id);
  assert.ok(bundle.projectMap.entrypoints.length <= 500);
  assert.ok(bundle.projectMap.securityFacts.length <= 1_000);
  assert.ok(bundle.projectMap.callEdges.length <= 1_000);
  assert.equal('root' in bundle, false);
});
