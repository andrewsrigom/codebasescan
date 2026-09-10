import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCoverage } from '../../src/domain/coverage.ts';
import type { ScannerRun } from '../../src/domain/types.ts';

const runs: ScannerRun[] = [
  {
    id: 'builtin',
    name: 'Built-in patterns',
    status: 'completed',
    durationMs: 1,
    findings: 0,
    detail: 'Completed with zero candidates.',
  },
  {
    id: 'semgrep',
    name: 'Semgrep',
    status: 'failed',
    durationMs: 1,
    findings: 0,
    detail: 'Scanner failed.',
  },
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    status: 'skipped',
    durationMs: 0,
    findings: 0,
    detail: 'Disabled.',
  },
];

test('coverage keeps zero findings, scanner failure, and unsupported scope distinct', () => {
  const coverage = buildCoverage(runs, [], 'disabled');
  assert.equal(coverage.find((item) => item.id === 'builtin')?.status, 'COMPLETE');
  assert.equal(coverage.find((item) => item.id === 'project-profile')?.status, 'NOT RUN');
  assert.equal(coverage.find((item) => item.id === 'ast-security')?.status, 'NOT RUN');
  assert.equal(coverage.find((item) => item.id === 'saas-security')?.status, 'NOT RUN');
  assert.equal(coverage.find((item) => item.id === 'next-security')?.status, 'NOT RUN');
  assert.equal(coverage.find((item) => item.id === 'react-security')?.status, 'NOT RUN');
  assert.equal(coverage.find((item) => item.id === 'dependency-cruiser')?.status, 'NOT RUN');
  assert.equal(coverage.find((item) => item.id === 'jscpd')?.status, 'NOT RUN');
  assert.equal(coverage.find((item) => item.id === 'semgrep')?.status, 'FAILED');
  assert.equal(coverage.find((item) => item.id === 'gitleaks')?.status, 'DISABLED');
  assert.equal(coverage.find((item) => item.id === 'http-probe')?.status, 'NOT RUN');
  assert.equal(
    coverage.find((item) => item.id === 'infrastructure-as-code')?.status,
    'NOT SUPPORTED',
  );
  assert.equal(
    coverage.find((item) => item.id === 'dynamic-exploitation')?.status,
    'NOT PERFORMED',
  );
  assert.equal(coverage.find((item) => item.id === 'ai-context')?.status, 'DISABLED');
});
