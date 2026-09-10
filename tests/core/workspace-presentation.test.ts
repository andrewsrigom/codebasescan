import assert from 'node:assert/strict';
import test from 'node:test';
import { presentProjectProfile } from '../../src/domain/workspace-presentation.ts';
import type { ProjectProfile } from '../../src/domain/types.ts';

test('workspace presentation keeps project-map evidence without shipping the full graph', () => {
  const profile: ProjectProfile = {
    schemaVersion: 1,
    status: 'complete',
    languages: ['typescript'],
    frameworks: [],
    components: [],
    componentEdges: [],
    entrypoints: [
      {
        id: 'entrypoint',
        kind: 'next-route',
        file: 'app/api/items/route.ts',
        line: 1,
        name: 'POST',
        route: '/api/items',
        methods: ['POST'],
        dynamicParameters: [],
        symbolIds: ['route'],
      },
    ],
    symbols: [
      {
        id: 'route',
        file: 'app/api/items/route.ts',
        line: 1,
        name: 'POST',
        kind: 'function',
        exported: true,
      },
      {
        id: 'service',
        file: 'lib/items.ts',
        line: 3,
        name: 'saveItem',
        kind: 'function',
        exported: true,
      },
    ],
    imports: [],
    calls: [
      {
        id: 'call',
        file: 'app/api/items/route.ts',
        line: 2,
        callee: 'saveItem',
        callerSymbolId: 'route',
        targetSymbolId: 'service',
      },
    ],
    facts: [
      {
        id: 'auth',
        kind: 'authentication',
        file: 'lib/items.ts',
        line: 4,
        signal: 'requireUser',
        ownerSymbolId: 'service',
      },
      {
        id: 'database',
        kind: 'database',
        file: 'lib/items.ts',
        line: 5,
        signal: 'insert',
        ownerSymbolId: 'service',
      },
    ],
    filesAnalyzed: 2,
    nodesAnalyzed: 40,
    issues: [],
    truncated: false,
  };

  const presentation = presentProjectProfile(profile);
  assert.ok(presentation);
  assert.equal(presentation.symbolCount, 2);
  assert.equal(presentation.callCount, 1);
  assert.equal(presentation.factCount, 2);
  assert.deepEqual(presentation.entrypoints[0]?.factKinds.sort(), ['authentication', 'database']);
  assert.equal(presentation.entrypoints[0]?.sensitiveOperations, 1);
  assert.equal('symbols' in presentation, false);
  assert.equal('calls' in presentation, false);
  assert.equal('facts' in presentation, false);
  assert.equal('imports' in presentation, false);
});
