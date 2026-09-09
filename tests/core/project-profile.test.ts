import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import { snapshotOf } from '../helpers.ts';

test('project profile maps frameworks, entry points, symbols, calls, and security facts', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/profile-nextjs'));
  const { profile, run } = profileProject(snapshot);
  assert.equal(profile.status, 'complete');
  assert.equal(run.status, 'completed');
  assert.deepEqual(
    new Set(profile.frameworks.map((framework) => framework.id)),
    new Set(['nextjs-app-router', 'express', 'prisma', 'supabase']),
  );
  assert.ok(
    profile.entrypoints.some(
      (entrypoint) =>
        entrypoint.kind === 'next-route' &&
        entrypoint.route === '/api/projects/[id]' &&
        entrypoint.methods.includes('PATCH') &&
        entrypoint.dynamicParameters.includes('id'),
    ),
  );
  assert.ok(profile.entrypoints.some((entrypoint) => entrypoint.kind === 'server-action'));
  assert.ok(profile.entrypoints.some((entrypoint) => entrypoint.kind === 'middleware'));
  assert.ok(
    profile.entrypoints.some(
      (entrypoint) =>
        entrypoint.kind === 'express-route' && entrypoint.route === '/webhooks/:provider',
    ),
  );
  const requiredKinds = [
    'authentication',
    'authorization',
    'validation',
    'database',
    'outbound-request',
    'response',
    'secret-access',
  ];
  for (const kind of requiredKinds)
    assert.ok(
      profile.facts.some((fact) => fact.kind === kind),
      `missing ${kind}`,
    );
  const requireUser = profile.symbols.find(
    (symbol) => symbol.name === 'requireUser' && symbol.file.endsWith('/auth.ts'),
  );
  assert.ok(requireUser);
  assert.ok(
    profile.calls.some(
      (call) => call.callee === 'requireUser' && call.targetSymbolId === requireUser.id,
    ),
  );
});

test('syntax problems produce partial profile coverage instead of a clean result', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/profile-malformed'));
  const { profile, run } = profileProject(snapshot);
  assert.equal(profile.status, 'partial');
  assert.equal(run.status, 'partial');
  assert.ok(profile.issues.some((issue) => issue.includes('syntax diagnostic')));
});

test('unsupported source is explicit and imports cannot resolve outside the snapshot', () => {
  const unsupported = profileProject(snapshotOf('{"name":"fixture"}', 'package.json'));
  assert.equal(unsupported.profile.status, 'unsupported');
  assert.equal(unsupported.run.status, 'skipped');

  const escaped = profileProject(
    snapshotOf("import value from '../../outside.js'; value();", 'src/a.ts'),
  );
  assert.equal(escaped.profile.imports[0]?.resolvedFile, undefined);
});

test('profiling parses target code as data without executing it', () => {
  const result = profileProject(
    snapshotOf("throw new Error('must not run'); export function safe() { return 1; }"),
  );
  assert.equal(result.profile.status, 'complete');
  assert.ok(result.profile.symbols.some((symbol) => symbol.name === 'safe'));
});
