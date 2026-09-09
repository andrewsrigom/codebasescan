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

test('common root aliases resolve only to files already captured in the snapshot', () => {
  const snapshot = snapshotOf(
    `import { requireUser } from '@/lib/auth';
     import { removeTeam } from 'models/team';
     export async function POST() { await requireUser(); return removeTeam(); }`,
    'src/app/api/team/route.ts',
  );
  const auth = snapshotOf(`export async function requireUser() {}`, 'src/lib/auth.ts').files[0]!;
  const team = snapshotOf(`export async function removeTeam() {}`, 'models/team.ts').files[0]!;
  snapshot.files.push(auth, team);
  snapshot.totalBytes += auth.bytes + team.bytes;

  const imports = profileProject(snapshot).profile.imports;
  assert.equal(
    imports.find((item) => item.specifier === '@/lib/auth')?.resolvedFile,
    'src/lib/auth.ts',
  );
  assert.equal(
    imports.find((item) => item.specifier === 'models/team')?.resolvedFile,
    'models/team.ts',
  );
});

test('profiling parses target code as data without executing it', () => {
  const result = profileProject(
    snapshotOf("throw new Error('must not run'); export function safe() { return 1; }"),
  );
  assert.equal(result.profile.status, 'complete');
  assert.ok(result.profile.symbols.some((symbol) => symbol.name === 'safe'));
});

test('nested functions with use server directives become server-action entrypoints', () => {
  const result = profileProject(
    snapshotOf(
      `
      export default function Page() {
        async function deletePost() {
          'use server';
          await prisma.post.delete({ where: { id: 1 } });
        }
        return deletePost;
      }
    `,
      'src/app/posts/[id]/page.tsx',
    ),
  );
  const action = result.profile.entrypoints.find(
    (entrypoint) => entrypoint.kind === 'server-action' && entrypoint.name === 'deletePost',
  );
  assert.equal(action?.file, 'src/app/posts/[id]/page.tsx');
  assert.equal(action?.symbolIds.length, 1);
});

test('catch clauses are recorded as error-handling facts', () => {
  const result = profileProject(
    snapshotOf(
      `export async function POST() {
        try { return await database.project.findMany(); }
        catch { return Response.json({ error: 'failed' }); }
      }`,
      'src/app/api/projects/route.ts',
    ),
  );
  const handler = result.profile.symbols.find((symbol) => symbol.name === 'POST');
  const handling = result.profile.facts.find((fact) => fact.kind === 'error-handling');
  assert.equal(handling?.ownerSymbolId, handler?.id);
});

test('Next route wrappers, aliases, and destructured handlers are mapped', () => {
  const wrappedSnapshot = snapshotOf(
    `
      import { auth } from './auth';
      export const DELETE = auth(async (request) => {
        return database.user.delete({ where: { id: request.id } });
      });
    `,
    'src/app/api/user/route.ts',
  );
  const wrapped = profileProject(wrappedSnapshot).profile;
  const wrappedRoute = wrapped.entrypoints.find((entrypoint) => entrypoint.kind === 'next-route');
  assert.deepEqual(wrappedRoute?.methods, ['DELETE']);
  assert.equal(wrappedRoute?.symbolIds.length, 1);
  assert.ok(
    wrapped.facts.some(
      (fact) => fact.kind === 'authentication' && fact.ownerSymbolId === wrappedRoute?.symbolIds[0],
    ),
  );

  const direct = profileProject(
    snapshotOf(`export const PUT = async () => Response.json({ ok: true });`, 'app/api/route.ts'),
  ).profile.entrypoints[0];
  assert.deepEqual(direct?.methods, ['PUT']);
  assert.equal(direct?.symbolIds.length, 1);

  const alias = profileProject(
    snapshotOf(
      `async function handler() { return Response.json({ ok: true }); }
       export { handler as GET, handler as POST };`,
      'app/route.ts',
    ),
  ).profile.entrypoints[0];
  assert.deepEqual(alias?.methods, ['GET', 'POST']);
  assert.equal(alias?.symbolIds.length, 1);

  const destructured = profileProject(
    snapshotOf(`export const { GET, POST } = handlers;`, 'app/auth/route.ts'),
  ).profile.entrypoints[0];
  assert.deepEqual(destructured?.methods, ['GET', 'POST']);
});

test('Pages API method switches are mapped without executing handlers', () => {
  const profile = profileProject(
    snapshotOf(
      `export default async function handler(req, res) {
        switch (req.method) {
          case 'GET': return list(req, res);
          case 'DELETE': return remove(req, res);
        }
      }`,
      'pages/api/teams/[id].ts',
    ),
  ).profile;
  assert.deepEqual(profile.entrypoints[0]?.methods, ['GET', 'DELETE']);
  assert.equal(profile.entrypoints[0]?.route, '/teams/[id]');
});

test('common session guards and scoped helper calls become structural facts', () => {
  const profile = profileProject(
    snapshotOf(
      `export async function DELETE(request) {
        const session = await getSession(request);
        await findOwnedRecord({ where: { id: request.id, userId: session.user.id } });
        return database.record.delete({ where: { id: request.id } });
      }`,
      'src/app/api/records/[id]/route.ts',
    ),
  ).profile;
  assert.ok(profile.facts.some((fact) => fact.kind === 'authentication'));
  assert.ok(profile.facts.some((fact) => fact.kind === 'resource-scope'));
});
