import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanFeatureFlags } from '../../src/scanners/feature-flags.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('feature flag analysis links JSON declarations with literal source usages', () => {
  const snapshot = snapshotFromFiles({
    'catalog/plan.json': JSON.stringify({
      featureFlags: { analytics: true, payments: false },
    }),
    'src/features.ts': `
export function showAnalytics() { return isFeatureEnabled('analytics'); }
export function showPayments() { if (isFeatureEnabled('payments')) return true; return false; }
`,
  });
  const result = scanFeatureFlags(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.status, 'complete');
  assert.equal(result.analysis.summary.declaredFlags, 2);
  assert.equal(result.analysis.summary.staticUsages, 2);
  assert.equal(result.analysis.summary.matchedFlags, 2);
  assert.equal(result.analysis.summary.defaultConflicts, 0);
  assert.equal(result.analysis.usages.find((usage) => usage.key === 'payments')?.context, 'guard');
  assert.equal(result.run.findings, 0);
});

test('TypeScript runtime definitions pair through literal by-key lookups', () => {
  const snapshot = snapshotFromFiles({
    'src/runtime-flags.ts': `
const knownRuntimeFlagDefinitions = [
  { key: 'billing.visibility', defaultStatus: 'disabled' },
] as const;
export function definition() {
  return getRuntimeFlagDefinitionByKey('billing.visibility');
}
export function evaluate(input: { key: string }) {
  return evaluateRuntimeFeatureFlag({ key: input.key, defaultStatus: 'disabled' });
}
`,
  });
  const result = scanFeatureFlags(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.summary.declaredFlags, 1);
  assert.equal(result.analysis.summary.matchedFlags, 1);
  assert.equal(result.analysis.summary.dynamicUsages, 1);
  assert.equal(result.analysis.flags[0]?.status, 'matched');
});

test('feature flag default conflicts require unambiguous literal evidence', () => {
  const snapshot = snapshotFromFiles({
    'flags.json': JSON.stringify({ featureFlags: { checkout: false } }),
    'src/a.ts': `export const a = getFeatureFlag('checkout', true);`,
    'src/b.ts': `export const b = getFeatureFlag('checkout', false);`,
  });
  const result = scanFeatureFlags(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.summary.defaultConflicts, 1);
  assert.equal(result.analysis.flags[0]?.status, 'default-conflict');
  assert.ok(result.analysis.declarations[0]?.default?.fingerprint);
  assert.equal(result.analysis.declarations[0]?.default?.display, 'false');
});

test('plan-specific declaration differences are not default conflicts', () => {
  const snapshot = snapshotFromFiles({
    'catalog/launch.json': JSON.stringify({ featureFlags: { analytics: true } }),
    'catalog/minimal.json': JSON.stringify({ featureFlags: { analytics: false } }),
    'src/features.ts': `export const enabled = isFeatureEnabled('analytics');`,
  });
  const result = scanFeatureFlags(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.summary.defaultConflicts, 0);
  assert.equal(result.analysis.flags[0]?.status, 'matched');
});

test('unsupported and malformed feature flag coverage remain explicit', () => {
  const plain = snapshotFromFiles({ 'src/plain.ts': 'export const enabled = true;' });
  const unsupported = scanFeatureFlags(plain, profileProject(plain).profile);
  assert.equal(unsupported.analysis.status, 'unsupported');
  assert.equal(unsupported.run.status, 'skipped');

  const malformed = snapshotFromFiles({
    'src/feature-flags.ts': `export const featureFlags = { analytics: 'unterminated`,
  });
  const partial = scanFeatureFlags(malformed, profileProject(malformed).profile);
  assert.equal(partial.analysis.status, 'partial');
  assert.equal(partial.analysis.parseFailures, 1);
});
