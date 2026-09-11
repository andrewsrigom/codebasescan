import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readdir, readFile } from 'node:fs/promises';
import { buildRuleQualityReport, declaredFixtureRuleKeys } from '../../src/domain/rule-quality.ts';
import {
  parseRuleQualityReport,
  ruleQualityJsonSchema,
} from '../../src/domain/rule-quality-schema.ts';
import { sampleReport } from '../helpers.ts';

async function groundTruthFiles(directory: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await groundTruthFiles(target)));
    else if (entry.name === 'ground-truth.json') files.push(target);
  }
  return files;
}

function sourceForRule(ruleId: string): string | null {
  if (ruleId.startsWith('GHSA-')) return null;
  for (const [prefix, source] of [
    ['TW-A11Y', 'accessibility'],
    ['TW-AST', 'ast'],
    ['TW-NEXT', 'next'],
    ['TW-REACT', 'react'],
    ['TW-SAAS', 'saas'],
    ['TW-PRIV', 'privacy'],
    ['TW-REL', 'reliability'],
    ['TW-ENV', 'environment'],
    ['TW-P', 'posture'],
  ] as const)
    if (ruleId.startsWith(prefix)) return source;
  return 'builtin';
}

test('rule quality groups applied findings and preserves human dispositions', () => {
  const report = sampleReport();
  report.findings.push({
    ...structuredClone(report.findings[0]!),
    id: 'finding-copy',
    disposition: 'false_positive',
  });

  const quality = parseRuleQualityReport(buildRuleQualityReport(report));
  assert.equal(quality.kind, 'codebasescan-rule-quality');
  assert.equal(quality.auditId, report.auditId);
  assert.equal(quality.summary.appliedRules, 1);
  assert.equal(quality.summary.withHumanDisposition, 1);
  assert.equal(quality.rules[0]?.observedFindings, 2);
  assert.equal(quality.rules[0]?.humanDispositions.false_positive, 1);
  assert.ok(quality.rules[0]?.limitations.length);
});

test('rule quality exposes measured and explicitly unmeasured fixture status', () => {
  const report = sampleReport();
  const dynamicExecution = buildRuleQualityReport(report);
  assert.equal(dynamicExecution.rules[0]?.declaredFixtureMetrics.status, 'measured');

  report.findings[0] = {
    ...report.findings[0]!,
    ruleId: 'TW-001',
  };
  const measured = buildRuleQualityReport(report);
  assert.equal(measured.rules[0]?.declaredFixtureMetrics.status, 'measured');

  report.findings[0] = {
    ...report.findings[0]!,
    ruleId: 'TW-UNMEASURED',
  };
  const unmeasured = buildRuleQualityReport(report);
  assert.equal(unmeasured.rules[0]?.declaredFixtureMetrics.status, 'not_measured');

  report.findings[0] = {
    ...report.findings[0]!,
    source: 'web',
    ruleId: 'TW-WEB001',
  };
  const unitOnly = buildRuleQualityReport(report);
  assert.equal(unitOnly.rules[0]?.declaredFixtureMetrics.status, 'not_measured');
});

test('rule quality accepts web posture and imported Axe findings', () => {
  const report = sampleReport();

  for (const source of ['web', 'axe'] as const) {
    report.findings[0] = {
      ...report.findings[0]!,
      source,
      ruleId: source === 'web' ? 'TW-WEB001' : 'axe.button-name',
    };
    assert.equal(parseRuleQualityReport(buildRuleQualityReport(report)).rules[0]?.source, source);
  }
});

test('rule quality JSON Schema is versioned', () => {
  const schema = ruleQualityJsonSchema() as {
    properties?: { schemaVersion?: { const?: number } };
  };
  assert.equal(schema.properties?.schemaVersion?.const, 3);
});

test('declared per-rule metrics stay synchronized with benchmark ground truth', async () => {
  const expected = new Set<string>();
  for (const file of await groundTruthFiles(path.resolve('benchmarks'))) {
    const truth = JSON.parse(await readFile(file, 'utf8')) as { expectedRuleIds?: unknown };
    if (!Array.isArray(truth.expectedRuleIds)) continue;
    for (const ruleId of truth.expectedRuleIds) {
      if (typeof ruleId !== 'string') continue;
      const source = sourceForRule(ruleId);
      if (source) expected.add(`${source}:${ruleId}`);
    }
  }
  assert.deepEqual([...declaredFixtureRuleKeys].sort(), [...expected].sort());
});
