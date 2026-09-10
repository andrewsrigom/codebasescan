import test from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectDataMap } from '../../src/domain/data-map.ts';
import type { ProjectDeclaredContext, ProjectFact } from '../../src/domain/types.ts';

const facts: ProjectFact[] = [
  {
    id: 'fact-secret',
    kind: 'secret-access',
    file: 'src/server.ts',
    line: 2,
    signal: 'process.env.SERVICE_TOKEN',
  },
  {
    id: 'fact-outbound',
    kind: 'outbound-request',
    file: 'src/server.ts',
    line: 4,
    signal: 'fetch',
  },
  {
    id: 'fact-storage',
    kind: 'browser-storage',
    file: 'src/client.tsx',
    line: 8,
    signal: 'localStorage.setItem',
  },
  {
    id: 'fact-unrelated',
    kind: 'validation',
    file: 'src/server.ts',
    line: 1,
    signal: 'schema.parse',
  },
];
const context: ProjectDeclaredContext = {
  features: ['authentication'],
  roles: ['member'],
  sensitiveData: ['credentials', 'personal'],
  storageBoundaries: ['postgres'],
  externalServices: ['email-provider'],
  priorityPaths: [],
  outOfScopePaths: [],
};

test('data map separates observed operations from declared context', () => {
  const first = buildProjectDataMap(facts, context);
  const second = buildProjectDataMap(facts, context);
  assert.deepEqual(first, second);
  assert.equal(first.entries.length, 3);
  assert.deepEqual(first.summary, {
    'sensitive-read': 1,
    'outbound-transfer': 1,
    'browser-storage': 1,
  });
  assert.deepEqual(first.entries[0]?.dataClasses, ['credentials']);
  assert.equal(first.entries[0]?.provenance, 'observed');
  assert.deepEqual(first.declaredData, ['credentials', 'personal']);
  assert.deepEqual(first.declaredBoundaries.externalServices, ['email-provider']);
});
