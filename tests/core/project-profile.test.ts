import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import { effectiveEntrypointFacts } from '../../src/domain/project-graph.ts';
import { snapshotFromFiles, snapshotOf } from '../helpers.ts';

test('project profile maps frameworks, entry points, symbols, calls, and security facts', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/profile-nextjs'));
  const { profile, run } = profileProject(snapshot);
  assert.equal(profile.status, 'complete');
  assert.equal(run.status, 'completed');
  assert.deepEqual(
    new Set(profile.frameworks.map((framework) => framework.id)),
    new Set(['nextjs-app-router', 'react', 'express', 'prisma', 'supabase']),
  );
  const next = profile.frameworks.find((framework) => framework.id === 'nextjs-app-router');
  assert.deepEqual(next?.versionCoverage, {
    requested: '16.3.4',
    detectedMajor: 16,
    status: 'supported',
    supportedMajors: [13, 14, 15, 16],
    detail: "Framework major 16 is inside Traceward's declared static-rule support matrix.",
  });
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

test('declarative TypeScript path aliases resolve without loading config code', () => {
  const snapshot = snapshotFromFiles({
    'tsconfig.json': JSON.stringify({
      compilerOptions: { baseUrl: '.', paths: { '#security/*': ['src/security/*'] } },
    }),
    'src/app/api/team/route.ts': `
      import { requireUser } from '#security/auth';
      export async function DELETE() { await requireUser(); return Response.json({ ok: true }); }
    `,
    'src/security/auth.ts': `export async function requireUser() { return { id: '1' }; }`,
  });

  const result = profileProject(snapshot);
  assert.equal(result.profile.imports[0]?.resolvedFile, 'src/security/auth.ts');
  assert.equal(result.profile.status, 'complete');
});

test('captured workspace package exports resolve without loading package code', () => {
  const snapshot = snapshotFromFiles({
    'packages/security/package.json': JSON.stringify({
      name: '@fixture/security',
      exports: './src/index.ts',
    }),
    'packages/security/src/index.ts': `export async function requireUser() { return { id: '1' }; }`,
    'apps/web/tsconfig.json': JSON.stringify({
      compilerOptions: { paths: { '@/*': ['./src/*'] } },
    }),
    'apps/web/src/lib/security.ts': `
      import { requireUser } from '@fixture/security';
      export { requireUser };
    `,
    'apps/web/src/app/api/account/route.ts': `
      import { requireUser } from '@/lib/security';
      export async function POST() {
        await requireUser();
        return database.account.update({ data: { active: true } });
      }
    `,
  });
  const profile = profileProject(snapshot).profile;
  assert.ok(
    profile.imports.some(
      (item) =>
        item.specifier === '@fixture/security' &&
        item.resolvedFile === 'packages/security/src/index.ts',
    ),
  );
  const entrypoint = profile.entrypoints.find((item) => item.kind === 'next-route');
  assert.ok(entrypoint);
  assert.ok(
    effectiveEntrypointFacts(profile, entrypoint).some((fact) => fact.kind === 'authentication'),
  );
});

test('declarative SaaS semantics recognize project vocabulary and helpers', () => {
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({ scripts: { test: 'node --test', build: 'next build' } }),
    'traceward.config.json': JSON.stringify({
      schemaVersion: 1,
      vocabulary: { tenantKeys: ['customerWorkspaceKey'] },
      helpers: {
        authorization: ['requireMembership'],
        resourceScope: ['scopeToCustomerWorkspace'],
        rateLimit: ['consumeQuota'],
        idempotency: ['claimDelivery'],
        csrf: ['assertSameOrigin'],
      },
      expectedUnauthenticatedRoutes: ['/api/status'],
      context: {
        features: ['authentication', 'tenancy', 'billing'],
        roles: ['admin', 'member'],
        sensitiveData: ['personal', 'financial'],
        storageBoundaries: ['postgres'],
        externalServices: ['stripe'],
        priorityPaths: ['src/app/api/*'],
        outOfScopePaths: [],
      },
      verification: { packageManager: 'npm', testScripts: ['test'], buildScripts: ['build'] },
    }),
    'src/app/api/workspaces/[id]/route.ts': `
      export async function PATCH() {
        await requireMembership();
        await consumeQuota();
        await assertSameOrigin();
        await claimDelivery();
        return database.workspace.update({
          where: { customerWorkspaceKey: 'workspace_1' },
          data: { name: 'Updated' }
        });
      }
    `,
    'src/components/preferences.ts': `
      export function savePreferences(value: string) {
        localStorage.setItem('preferences', value);
      }
    `,
  });

  const profile = profileProject(snapshot).profile;
  for (const kind of ['authorization', 'rate-limit', 'idempotency', 'csrf', 'resource-scope'])
    assert.ok(
      profile.facts.some((fact) => fact.kind === kind),
      `missing configured ${kind} fact`,
    );
  assert.ok(profile.saasSemantics);
  assert.deepEqual(profile.saasSemantics.sources, ['traceward.config.json']);
  assert.deepEqual(profile.saasSemantics.expectedUnauthenticatedRoutes, ['/api/status']);
  assert.deepEqual(profile.saasSemantics.context?.roles, ['admin', 'member']);
  assert.deepEqual(profile.saasSemantics.verification?.testScripts, ['test']);
  assert.equal(profile.dataMap?.declaredData.includes('financial'), true);
  assert.equal(profile.dataMap?.declaredBoundaries.storage[0], 'postgres');
  assert.equal(profile.dataMap?.summary['persistent-storage'], 1);
  assert.equal(profile.dataMap?.summary['browser-storage'], 1);
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

test('profile recognizes focused Node frameworks and tRPC procedure boundaries', () => {
  const snapshot = snapshotFromFiles({
    'package.json': JSON.stringify({
      dependencies: {
        'drizzle-orm': '1.0.0',
        'next-auth': '5.0.0',
        '@trpc/server': '11.0.0',
        graphql: '16.0.0',
        zod: '4.0.0',
        joi: '18.0.0',
        valibot: '1.0.0',
      },
    }),
    'src/router.ts': `
      export const removeUser = protectedProcedure
        .input(UserInput)
        .mutation(async ({ input, ctx }) => {
          return db.delete(users).where(eq(users.id, input.id));
        });
    `,
  });
  const profile = profileProject(snapshot).profile;
  assert.deepEqual(
    new Set(profile.frameworks.map((framework) => framework.id)),
    new Set(['drizzle', 'authjs', 'trpc', 'graphql', 'zod', 'joi', 'valibot']),
  );
  const procedure = profile.entrypoints.find((entrypoint) => entrypoint.kind === 'trpc-procedure');
  assert.ok(procedure);
  assert.deepEqual(procedure.methods, ['POST']);
  const facts = effectiveEntrypointFacts(profile, procedure);
  assert.ok(facts.some((fact) => fact.kind === 'authentication'));
  assert.ok(facts.some((fact) => fact.kind === 'validation'));
  assert.ok(facts.some((fact) => fact.kind === 'database'));
});

test('framework version coverage distinguishes ambiguous and unsupported majors', () => {
  const profile = profileProject(
    snapshotFromFiles({
      'package.json': JSON.stringify({
        dependencies: { next: '>=15 <17', react: '20.0.0', express: '^5.1.0' },
      }),
      'src/app/page.tsx': `export default function Page() { return <main />; }`,
    }),
  ).profile;
  assert.equal(
    profile.frameworks.find((framework) => framework.id === 'nextjs-app-router')?.versionCoverage
      ?.status,
    'unverified',
  );
  assert.equal(
    profile.frameworks.find((framework) => framework.id === 'react')?.versionCoverage?.status,
    'partial',
  );
  assert.equal(
    profile.frameworks.find((framework) => framework.id === 'express')?.versionCoverage?.status,
    'supported',
  );
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

test('billing provider mutations are mapped as sensitive facts', () => {
  const profile = profileProject(
    snapshotOf(
      `export async function POST() {
        return stripe.checkout.sessions.create({ line_items: [] });
      }`,
      'src/app/api/checkout/route.ts',
    ),
  ).profile;
  assert.ok(profile.facts.some((fact) => fact.kind === 'billing'));
  assert.ok(
    effectiveEntrypointFacts(profile, profile.entrypoints[0]!).some(
      (fact) => fact.kind === 'billing',
    ),
  );
});

test('regular expression execution is not classified as operating-system command execution', () => {
  const result = profileProject(
    snapshotOf(
      `const METHOD = /^(GET|POST) /;
       export function sanitize(value: string) { return METHOD.exec(value)?.[1] ?? ''; }
       export async function GET() { return Response.json({ method: sanitize('GET /') }); }`,
      'src/app/api/example/route.ts',
    ),
  );
  assert.ok(!result.profile.facts.some((fact) => fact.kind === 'command-execution'));
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
  ).profile.entrypoints;
  assert.deepEqual(
    alias.flatMap((entrypoint) => entrypoint.methods),
    ['GET', 'POST'],
  );
  assert.ok(alias.every((entrypoint) => entrypoint.symbolIds.length === 1));

  const destructured = profileProject(
    snapshotOf(`export const { GET, POST } = handlers;`, 'app/auth/route.ts'),
  ).profile.entrypoints;
  assert.deepEqual(
    destructured.flatMap((entrypoint) => entrypoint.methods),
    ['GET', 'POST'],
  );
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

test('descriptive security wrapper names become structural facts', () => {
  const profile = profileProject(
    snapshotOf(
      `export async function POST(request) {
        await authenticateDeveloperApiRequest(request);
        await requireSuperAdminSession(request.headers);
        const input = parseBoundedProjectInput(request);
        await database.project.update({ data: input });
      }`,
      'src/app/api/admin/projects/route.ts',
    ),
  ).profile;
  const kinds = new Set(profile.facts.map((fact) => fact.kind));
  assert.ok(kinds.has('authentication'));
  assert.ok(kinds.has('authorization'));
  assert.ok(kinds.has('validation'));
});
