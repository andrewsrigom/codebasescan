import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { preferStructuralFindings, scanAstSecurity } from '../../src/scanners/ast-security.ts';
import { scanPatterns } from '../../src/scanners/builtin.ts';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import { snapshotFromFiles, snapshotOf } from '../helpers.ts';

test('AST authorization rules connect mutating entry points to sensitive operations', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/ast-auth-vulnerable'));
  const profile = profileProject(snapshot).profile;
  const result = scanAstSecurity(snapshot, profile);
  assert.equal(result.run.status, 'completed');
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-AST001'));
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-AST002'));
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-AST003'));
  assert.ok(result.findings.every((finding) => finding.evidence[0]?.kind === 'inferred'));
  assert.ok(result.findings.every((finding) => finding.disposition === 'needs_review'));
});

test('AST authorization covers nested inline server actions', () => {
  const snapshot = snapshotOf(
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
  );
  const profile = profileProject(snapshot).profile;
  const finding = scanAstSecurity(snapshot, profile).findings.find(
    (candidate) => candidate.ruleId === 'TW-AST001',
  );
  assert.equal(finding?.evidence[0]?.file, 'src/app/posts/[id]/page.tsx');
});

test('API Gateway Lambda mutations require mapped authentication', () => {
  const vulnerableSnapshot = snapshotOf(
    `
      import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
      export const handler: APIGatewayProxyHandlerV2 = async (event) => {
        return client.send(new UpdateCommand({ Item: event.body }));
      };
    `,
    'src/functions/record-usage-handler.ts',
  );
  const vulnerable = scanAstSecurity(
    vulnerableSnapshot,
    profileProject(vulnerableSnapshot).profile,
  ).findings;
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-AST001'));

  const protectedSnapshot = snapshotOf(
    `
      import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
      export const handler: APIGatewayProxyHandlerV2 = async (event) => {
        verifyToken(event.headers.authorization);
        return client.send(new UpdateCommand({ Item: event.body }));
      };
    `,
    'src/functions/record-usage-handler.ts',
  );
  const protectedFindings = scanAstSecurity(
    protectedSnapshot,
    profileProject(protectedSnapshot).profile,
  ).findings;
  assert.ok(!protectedFindings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('read-only server action candidates do not carry high mutation severity', () => {
  const snapshot = snapshotOf(
    `'use server'; export async function checkTable() { return prisma.post.findFirst(); }`,
    'src/app/actions.ts',
  );
  const finding = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings.find(
    (candidate) => candidate.ruleId === 'TW-AST001',
  );
  assert.equal(finding?.severity, 'medium');
  assert.match(finding?.title ?? '', /operation/);
});

test('recognized two-hop auth, permission, and owner scope avoid AST gap candidates', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/profile-nextjs'));
  const profile = profileProject(snapshot).profile;
  const result = scanAstSecurity(snapshot, profile);
  assert.equal(result.run.status, 'completed');
  assert.deepEqual(result.findings, []);
});

test('authorization analysis follows and evidences five explicit call hops', () => {
  const snapshot = snapshotOf(
    `
      export async function POST(request: Request) { return first(request); }
      function first(request) { return second(request); }
      function second(request) { return third(request); }
      function third(request) { return fourth(request); }
      function fourth(request) { return database.account.delete({ where: { id: request.id } }); }
    `,
    'src/app/api/accounts/route.ts',
  );
  const finding = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings.find(
    (candidate) => candidate.ruleId === 'TW-AST001',
  );
  assert.ok(finding);
  assert.ok(
    finding.evidence.filter((item) => item.observation.startsWith('Call path')).length >= 4,
  );
});

test('matching authenticated middleware protects a Next route but unrelated middleware does not', () => {
  const protectedSnapshot = snapshotFromFiles({
    'src/middleware.ts': `
      export function middleware(request) { requireUser(request); return NextResponse.next(); }
      export const config = { matcher: ['/api/:path*'] };
    `,
    'src/app/api/accounts/route.ts': `
      export async function DELETE(request) {
        return database.account.delete({ where: { id: request.id } });
      }
    `,
  });
  const protectedFindings = scanAstSecurity(
    protectedSnapshot,
    profileProject(protectedSnapshot).profile,
  ).findings;
  assert.ok(!protectedFindings.some((finding) => finding.ruleId === 'TW-AST001'));

  const unrelatedSnapshot = snapshotFromFiles({
    'src/middleware.ts': `
      export function middleware(request) { requireUser(request); return NextResponse.next(); }
      export const config = { matcher: ['/dashboard/:path*'] };
    `,
    'src/app/api/accounts/route.ts': `
      export async function DELETE(request) {
        return database.account.delete({ where: { id: request.id } });
      }
    `,
  });
  const unrelatedFindings = scanAstSecurity(
    unrelatedSnapshot,
    profileProject(unrelatedSnapshot).profile,
  ).findings;
  assert.ok(unrelatedFindings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('middleware data access is not attributed to a mutating route', () => {
  const snapshot = snapshotFromFiles({
    'src/middleware.ts': `
      export async function middleware(request) {
        await db.website.findFirst({ where: { host: request.headers.get('host') } });
        return NextResponse.next();
      }
      export const config = { matcher: ['/api/:path*'] };
    `,
    'src/app/api/health/route.ts': `
      export async function POST() { return Response.json({ ok: true }); }
    `,
  });
  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-AST001'));
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-AST003'));
});

test('ordered Express-style middleware can provide a request credential guard', () => {
  const protectedSnapshot = snapshotOf(`
    app.use('/api/*', async (c, next) => {
      if (c.req.header('X-App-Token') !== writeToken) {
        return c.json({ error: 'denied' }, 403);
      }
      return next();
    });
    app.patch('/api/items/:id', async (c) =>
      context.db.update(items).set({ active: true }).where(eq(items.id, c.req.param('id')))
    );
  `);
  const protectedFindings = scanAstSecurity(
    protectedSnapshot,
    profileProject(protectedSnapshot).profile,
  ).findings;
  assert.ok(!protectedFindings.some((finding) => finding.ruleId === 'TW-AST001'));
  assert.ok(protectedFindings.some((finding) => finding.ruleId === 'TW-AST003'));

  const lateSnapshot = snapshotOf(`
    app.patch('/api/items/:id', async (c) =>
      context.db.update(items).set({ active: true }).where(eq(items.id, c.req.param('id')))
    );
    app.use('/api/*', async (c, next) => {
      if (c.req.header('X-App-Token') !== writeToken) return c.json({ error: 'denied' }, 403);
      return next();
    });
  `);
  const lateFindings = scanAstSecurity(lateSnapshot, profileProject(lateSnapshot).profile).findings;
  assert.ok(lateFindings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('authentication wrappers protect mapped Next route callbacks', () => {
  const snapshot = snapshotOf(
    `
      import { auth } from './auth';
      export const DELETE = auth(async (request) => {
        return database.user.delete({ where: { id: request.id } });
      });
    `,
    'src/app/api/user/route.ts',
  );
  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('Pages API method switches participate in bounded authorization analysis', () => {
  const vulnerable = snapshotOf(
    `export default async function handler(req, res) {
      switch (req.method) { case 'DELETE': return remove(req, res); }
    }
    async function remove(req, res) {
      return database.team.delete({ where: { id: req.query.id } });
    }`,
    'pages/api/teams/[id].ts',
  );
  assert.ok(
    scanAstSecurity(vulnerable, profileProject(vulnerable).profile).findings.some(
      (finding) => finding.ruleId === 'TW-AST001',
    ),
  );

  const safe = snapshotOf(
    `export default async function handler(req, res) {
      switch (req.method) { case 'DELETE': return remove(req, res); }
    }
    async function remove(req, res) {
      const member = await throwIfNoTeamAccess(req, res);
      throwIfNotAllowed(member, 'team', 'delete');
      return database.team.delete({ where: { id: req.query.id } });
    }`,
    'pages/api/teams/[id].ts',
  );
  assert.ok(
    !scanAstSecurity(safe, profileProject(safe).profile).findings.some(
      (finding) => finding.ruleId === 'TW-AST001',
    ),
  );
});

test('root-alias calls participate in bounded authorization analysis', () => {
  const snapshot = snapshotOf(
    `import { removeUser } from '@/lib/users';
     export async function DELETE() { return removeUser(); }`,
    'src/app/api/user/route.ts',
  );
  const users = snapshotOf(
    `export async function removeUser() {
       await requireUser();
       return database.user.delete({ where: { id: 'self' } });
     }`,
    'src/lib/users.ts',
  ).files[0]!;
  snapshot.files.push(users);
  snapshot.totalBytes += users.bytes;

  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('public authentication flows are not required to have an existing session', () => {
  const snapshot = snapshotOf(
    `export default async function handler(req, res) {
       if (req.method === 'POST') return database.passwordReset.create({ data: req.body });
     }`,
    'pages/api/auth/forgot-password.ts',
  );
  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('explicit public submission routes are not required to have an existing session', () => {
  const snapshot = snapshotOf(
    `export async function POST(request) {
       const input = validateWaitlistEntry(await request.json());
       return database.waitlist.create({ data: input });
     }`,
    'src/app/api/waitlist/route.ts',
  );
  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('declarative public routes avoid project-specific missing-login noise', () => {
  const snapshot = snapshotFromFiles({
    'codebasescan.config.json': JSON.stringify({
      schemaVersion: 1,
      expectedUnauthenticatedRoutes: ['/api/partner/callback'],
    }),
    'src/app/api/partner/callback/route.ts': `
      export async function POST() {
        await database.callback.create({ data: { received: true } });
        return Response.json({ ok: true });
      }
    `,
  });
  const profile = profileProject(snapshot).profile;
  const findings = scanAstSecurity(snapshot, profile).findings;
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('explicit authorization or an ownership helper avoids dynamic-scope noise', () => {
  const authorized = snapshotOf(
    `export async function DELETE(request) {
       await throwIfNotAllowed(request.user, 'team', 'delete');
       return database.team.delete({ where: { id: request.id } });
     }`,
    'src/app/api/teams/[id]/route.ts',
  );
  assert.ok(
    !scanAstSecurity(authorized, profileProject(authorized).profile).findings.some(
      (finding) => finding.ruleId === 'TW-AST003',
    ),
  );

  const scoped = snapshotOf(
    `export async function DELETE(request) {
       const session = await getSession(request);
       await findOwnedRecord({ where: { id: request.id, userId: session.user.id } });
       return database.record.delete({ where: { id: request.id } });
     }`,
    'src/app/api/records/[id]/route.ts',
  );
  assert.ok(
    !scanAstSecurity(scoped, profileProject(scoped).profile).findings.some(
      (finding) => finding.ruleId === 'TW-AST003',
    ),
  );
});

test('read-only routes and webhook boundaries are not treated as missing login mutations', () => {
  const getSnapshot = snapshotOf(
    'export async function GET() { return prisma.project.findMany(); }',
    'src/app/api/projects/route.ts',
  );
  const getResult = scanAstSecurity(getSnapshot, profileProject(getSnapshot).profile);
  assert.deepEqual(getResult.findings, []);

  const webhookSnapshot = snapshotOf(
    'export async function POST() { return db.event.create({ data: {} }); }',
    'src/app/api/webhooks/provider/route.ts',
  );
  const webhookResult = scanAstSecurity(webhookSnapshot, profileProject(webhookSnapshot).profile);
  assert.deepEqual(webhookResult.findings, []);
});

test('billing mutations participate in missing authentication review', () => {
  const snapshot = snapshotOf(
    `export async function POST() {
      return stripe.checkout.sessions.create({ line_items: [] });
    }`,
    'src/app/api/checkout/route.ts',
  );
  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(findings.some((finding) => finding.ruleId === 'TW-AST001'));
});

test('unsupported and partial profiles never imply complete AST coverage', async () => {
  const unsupportedSnapshot = snapshotOf('{}', 'package.json');
  const unsupported = scanAstSecurity(
    unsupportedSnapshot,
    profileProject(unsupportedSnapshot).profile,
  );
  assert.equal(unsupported.run.status, 'skipped');

  const partialSnapshot = await captureSnapshot(path.resolve('fixtures/profile-malformed'));
  const partial = scanAstSecurity(partialSnapshot, profileProject(partialSnapshot).profile);
  assert.equal(partial.run.status, 'partial');
});

function astRuleIds(content: string, file = 'src/app/api/test/route.ts'): string[] {
  const snapshot = snapshotOf(content, file);
  return scanAstSecurity(snapshot, profileProject(snapshot).profile).findings.map(
    (finding) => finding.ruleId,
  );
}

test('AST traces direct request data into raw SQL, outbound requests, and redirects', () => {
  assert.ok(
    astRuleIds(`
      export async function POST(request: Request) {
        const body = await request.json();
        return db.$queryRawUnsafe(\`SELECT * FROM projects WHERE name = '${'${body.name}'}'\`);
      }
    `).includes('TW-AST004'),
  );
  assert.ok(
    astRuleIds(`
      export async function GET(request: Request) {
        const target = new URL(request.url).searchParams.get('target');
        return fetch(target);
      }
    `).includes('TW-AST005'),
  );
  assert.ok(
    astRuleIds(`
      export async function GET(request: Request) {
        const next = new URL(request.url).searchParams.get('next');
        return redirect(next);
      }
    `).includes('TW-AST006'),
  );
});

test('configured webhook delivery requires complete SSRF controls', () => {
  const unsafeSnapshot = snapshotOf(
    `
      export async function deliverWebhook(connection) {
        const destination = connection.externalId;
        return fetch(destination, { method: 'POST' });
      }
    `,
    'src/lib/webhooks/delivery.ts',
  );
  const unsafe = scanAstSecurity(unsafeSnapshot, profileProject(unsafeSnapshot).profile).findings;
  assert.ok(unsafe.some((finding) => finding.ruleId === 'TW-AST005'));

  const storedSnapshot = snapshotOf(
    `
      export async function deliverWebhook(input) {
        const resolved = await resolveConfiguredWebhookDestination(input.userId);
        return fetch(resolved.endpointUrl, { method: 'POST' });
      }
    `,
    'src/lib/webhook-destination.ts',
  );
  const stored = scanAstSecurity(storedSnapshot, profileProject(storedSnapshot).profile).findings;
  assert.ok(stored.some((finding) => finding.ruleId === 'TW-AST005'));

  const safeSnapshot = snapshotOf(
    `
      export async function deliverWebhook(destinationUrl) {
        await assertSafeExternalUrl(destinationUrl);
        return fetch(destinationUrl, { method: 'POST', redirect: 'manual' });
      }
    `,
    'src/lib/webhooks/delivery.ts',
  );
  const safe = scanAstSecurity(safeSnapshot, profileProject(safeSnapshot).profile).findings;
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-AST005'));
});

test('recognized destination guards and constant sinks avoid direct flow candidates', () => {
  const ids = astRuleIds(`
    export async function GET(request: Request) {
      const target = new URL(request.url).searchParams.get('target');
      assertSafeUrl(target);
      await fetch(target);
      const next = '/dashboard';
      return redirect(next);
    }
  `);
  assert.ok(!ids.includes('TW-AST005'));
  assert.ok(!ids.includes('TW-AST006'));
});

test('server-owned URLs may use the request URL only as their same-origin base', () => {
  const ids = astRuleIds(`
    export async function GET(request: Request) {
      const session = new URL('/api/auth/session', request.url);
      await fetch(session);
      const currentPath = encodeURIComponent(new URL(request.url).pathname);
      const base = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
      return redirect(new URL(\`${'${base}'}/login?from=${'${currentPath}'}\`, request.url));
    }
  `);
  assert.ok(!ids.includes('TW-AST005'));
  assert.ok(!ids.includes('TW-AST006'));

  assert.ok(
    astRuleIds(`
      export async function GET(request: Request) {
        const next = new URL(request.url).searchParams.get('next');
        return redirect(new URL(next, request.url));
      }
    `).includes('TW-AST006'),
  );
});

test('request paths stay on an explicit server-owned redirect origin', () => {
  const safeIds = astRuleIds(`
    function normalizeAppOrigin(value: string | undefined) {
      return value ?? 'https://app.example.test';
    }
    export async function GET(request: Request) {
      const appOrigin = normalizeAppOrigin(process.env.NEXT_PUBLIC_APP_URL);
      const coreAppUrl = appOrigin ?? 'http://localhost:3000';
      const target = new URL(
        request.nextUrl.pathname + request.nextUrl.search,
        coreAppUrl,
      );
      return redirect(target);
    }
  `);
  assert.ok(!safeIds.includes('TW-AST006'));

  const unsafeIds = astRuleIds(`
    export async function GET(request: Request) {
      const next = request.nextUrl.searchParams.get('next');
      const coreAppUrl = process.env.APP_URL ?? 'http://localhost:3000';
      return redirect(new URL(next, coreAppUrl));
    }
  `);
  assert.ok(unsafeIds.includes('TW-AST006'));
});

test('a request URL becomes an owned redirect after fixed host and protocol replacement', () => {
  const safeIds = astRuleIds(`
    export async function GET(request: Request) {
      const current = new URL(request.url);
      const port = current.port ? \`:${'${current.port}'}\` : '';
      const targetHost = \`app.localhost${'${port}'}\`;
      current.host = targetHost;
      current.protocol = 'http:';
      await fetch(current);
      return redirect(current);
    }
  `);
  assert.ok(!safeIds.includes('TW-AST005'));
  assert.ok(!safeIds.includes('TW-AST006'));

  const unsafeIds = astRuleIds(`
    export async function GET(request: Request) {
      const current = new URL(request.url);
      current.host = request.headers.get('host') ?? current.host;
      current.protocol = 'https:';
      return redirect(current);
    }
  `);
  assert.ok(unsafeIds.includes('TW-AST006'));
});

test('request data passed into an external client does not taint its response', () => {
  const ids = astRuleIds(`
    export async function POST(request: Request) {
      const body = await request.json();
      const session = await payment.sessions.create({ customer: body.customer });
      const destination = session.url as string;
      return redirect(destination);
    }
  `);
  assert.ok(!ids.includes('TW-AST006'));
});

test('strict host-label allowlisting avoids an open-redirect candidate', () => {
  const safeIds = astRuleIds(`
    export async function POST(prevState: unknown, formData: FormData) {
      const subdomain = formData.get('subdomain') as string;
      const safeSubdomain = subdomain.toLowerCase().replace(/[^a-z0-9-]/g, '');
      return redirect(\`https://${'${safeSubdomain}'}.example.test\`);
    }
  `);
  assert.ok(!safeIds.includes('TW-AST006'));

  const unsafeIds = astRuleIds(`
    export async function POST(prevState: unknown, formData: FormData) {
      const destination = (formData.get('next') as string).replace(/\\s/g, '');
      return redirect(destination);
    }
  `);
  assert.ok(unsafeIds.includes('TW-AST006'));
});

test('replacing the request origin with a server-owned backend avoids SSRF noise', () => {
  const safeIds = astRuleIds(`
    export async function GET(request: Request) {
      const backend = process.env.INTERNAL_BACKEND ?? 'https://backend.example.test';
      const destination = request.nextUrl.href.replace(request.nextUrl.origin, backend);
      return fetch(destination);
    }
  `);
  assert.ok(!safeIds.includes('TW-AST005'));

  const unsafeIds = astRuleIds(`
    export async function GET(request: Request) {
      const backend = new URL(request.url).searchParams.get('backend');
      const destination = request.nextUrl.href.replace(request.nextUrl.origin, backend);
      return fetch(destination);
    }
  `);
  assert.ok(unsafeIds.includes('TW-AST005'));
});

test('server-owned config origins keep request data confined to URL paths', () => {
  const ids = astRuleIds(`
    const GOOGLE_API_BASE = 'https://api.example.test/v1';

    function getAnalyticsConfig() {
      return { endpoint: process.env.ANALYTICS_ENDPOINT ?? 'https://analytics.example.test' };
    }

    async function fetchJson(url: string) {
      return fetch(url);
    }

    export async function GET(request: Request) {
      const itemId = new URL(request.url).searchParams.get('itemId') ?? '';
      const { endpoint } = getAnalyticsConfig();
      const analyticsUrl = new URL(\`${'${endpoint}'}/items/${'${encodeURIComponent(itemId)}'}\`);
      await fetch(analyticsUrl.toString());
      const providerUrl = new URL(\`${'${GOOGLE_API_BASE}'}/items/${'${encodeURIComponent(itemId)}'}\`);
      return fetchJson(providerUrl.toString());
    }
  `);
  assert.ok(!ids.includes('TW-AST005'));
});

test('server-owned application origins keep encoded job IDs out of SSRF findings', () => {
  const ids = astRuleIds(`
    function resolveAppOrigin() {
      return process.env.APP_ORIGIN ?? 'https://app.example.test';
    }

    export async function GET(request: Request) {
      const jobId = new URL(request.url).searchParams.get('jobId') ?? '';
      const appOrigin = resolveAppOrigin();
      const workerUrl = \`${'${appOrigin}'}/api/jobs?jobId=${'${encodeURIComponent(jobId)}'}\`;
      return fetch(workerUrl);
    }
  `);
  assert.ok(!ids.includes('TW-AST005'));

  const unsafeIds = astRuleIds(`
    export async function GET(request: Request) {
      const origin = new URL(request.url).searchParams.get('origin') ?? '';
      const workerUrl = \`${'${origin}'}/api/jobs\`;
      return fetch(workerUrl);
    }
  `);
  assert.ok(unsafeIds.includes('TW-AST005'));
});

test('AST identifies webhook ordering, upload constraints, and cookie attributes', () => {
  assert.ok(
    astRuleIds(
      `
        export async function POST(request: Request) {
          const body = await request.json();
          verifySignature(body);
          return db.event.create({ data: body });
        }
      `,
      'src/app/api/webhooks/provider/route.ts',
    ).includes('TW-AST008'),
  );
  assert.ok(
    astRuleIds(`
      export async function POST(request: Request) {
        const form = await request.formData();
        const file = form.get('file');
        return storage.upload(file.name, file);
      }
    `).includes('TW-AST007'),
  );
  assert.ok(
    astRuleIds(`
      export async function POST(request: Request) {
        const file = request.body;
        const name = request.headers.get('x-filename');
        return put(name, file, { access: 'public' });
      }
    `).includes('TW-AST007'),
  );
  assert.ok(
    astRuleIds(`
      export async function POST(request: Request) {
        cookies().set('session', request.headers.get('token'));
        return Response.json({ ok: true });
      }
    `).includes('TW-AST009'),
  );
});

test('safe webhook bytes, validated upload, and complete cookies avoid gap candidates', () => {
  const webhookIds = astRuleIds(
    `
      export async function POST(request: Request) {
        const raw = await request.text();
        verifySignature(raw, request.headers.get('signature'));
        const body = JSON.parse(raw);
        return db.event.create({ data: body });
      }
    `,
    'src/app/api/webhooks/provider/route.ts',
  );
  assert.ok(!webhookIds.includes('TW-AST008'));

  const tokenWebhookIds = astRuleIds(
    `
      export async function POST(request: Request) {
        const received = request.headers.get('authorization');
        if (!safeSecretEquals(received, process.env.WEBHOOK_TOKEN)) {
          return Response.json({ error: 'invalid' }, { status: 401 });
        }
        const body = await request.json();
        return db.event.create({ data: body });
      }
    `,
    'src/app/api/webhooks/provider/route.ts',
  );
  assert.ok(!tokenWebhookIds.includes('TW-AST008'));

  const hardenedIds = astRuleIds(`
    export async function POST(request: Request) {
      const form = await request.formData();
      const file = form.get('file');
      validateUpload(file);
      await storage.upload('generated-name', file);
      const options = { secure: true, httpOnly: true, sameSite: 'lax' };
      cookies().set('session', 'opaque', options);
      return Response.json({ ok: true });
    }
  `);
  assert.ok(!hardenedIds.includes('TW-AST007'));
  assert.ok(!hardenedIds.includes('TW-AST009'));

  const streamedIds = astRuleIds(`
    export async function POST(request: Request) {
      const file = request.body;
      const name = request.headers.get('x-filename');
      validateUpload(file, name, { fileSize: 1_000_000, mime: ['image/png'] });
      return put('generated-name', file);
    }
  `);
  assert.ok(!streamedIds.includes('TW-AST007'));

  const schemaIds = astRuleIds(`
    export async function POST(request: Request) {
      const form = await request.formData();
      const file = form.get('file');
      const parsed = FileSchema.safeParse({ file });
      if (!parsed.success) return Response.json({ error: 'invalid' }, { status: 400 });
      return put('generated-name', file);
    }
  `);
  assert.ok(!schemaIds.includes('TW-AST007'));

  const unrelatedSchemaIds = astRuleIds(`
    export async function POST(request: Request) {
      const form = await request.formData();
      const file = form.get('file');
      UserSchema.safeParse({ name: form.get('name') });
      return put(file.name, file);
    }
  `);
  assert.ok(unrelatedSchemaIds.includes('TW-AST007'));
});

test('webhook management APIs and response serialization are not inbound webhook parsing', () => {
  const ids = astRuleIds(
    `
      export default async function handler(req, res) {
        const endpoint = await createWebhook(req.body);
        return res.status(200).json({ data: endpoint });
      }
    `,
    'pages/api/teams/[slug]/webhooks/[endpointId].ts',
  );
  assert.ok(!ids.includes('TW-AST008'));
  const nextManagementIds = astRuleIds(
    `export async function PUT(request: Request) {
      const body = await request.json();
      return Response.json(await updateWebhookSettings(body));
    }`,
    'src/app/api/webhooks/route.ts',
  );
  assert.ok(!nextManagementIds.includes('TW-AST008'));
});

test('client modules referencing server environment values are identified', () => {
  const ids = astRuleIds(
    `'use client'; export const api = process.env.INTERNAL_API_SECRET;`,
    'src/components/client.tsx',
  );
  assert.ok(ids.includes('TW-AST010'));
  assert.ok(
    !astRuleIds(
      `'use client'; export const label = process.env.NEXT_PUBLIC_LABEL;`,
      'src/components/client.tsx',
    ).includes('TW-AST010'),
  );
  assert.ok(
    !astRuleIds(
      `'use client'; export const production = process.env.NODE_ENV === 'production';`,
      'src/components/client.tsx',
    ).includes('TW-AST010'),
  );
});

test('direct AST rules do not treat test code as deployed runtime code', () => {
  const snapshot = snapshotOf(
    `'use client'; export const api = process.env.INTERNAL_API_SECRET;`,
    'tests/client.test.tsx',
  );
  const profile = profileProject(snapshot).profile;
  snapshot.files[0]!.scope = 'test';
  assert.deepEqual(scanAstSecurity(snapshot, profile).findings, []);
});

test('AST traces request data into command, path, regex, and deserialization sinks', () => {
  const ids = astRuleIds(`
    export async function POST(request: Request) {
      const body = await request.json();
      exec(body.command);
      await fs.readFile(body.path);
      https.get(body.imageUrl);
      const matcher = new RegExp(body.pattern);
      const value = serializer.unserialize(body.payload);
      return Response.json({ matcher, value });
    }
  `);
  assert.ok(ids.includes('TW-AST011'));
  assert.ok(ids.includes('TW-AST012'));
  assert.ok(ids.includes('TW-AST013'));
  assert.ok(ids.includes('TW-AST014'));
});

test('AST follows request URLs into Node HTTP clients across files', () => {
  const snapshot = snapshotFromFiles({
    'src/routes/video.ts': `
      import { downloadAudio } from '../services/audio';
      app.post('/video', async (req, res) => {
        await downloadAudio(req.body.audioUrl);
        res.send({ ok: true });
      });
    `,
    'src/services/audio.ts': `
      import https from 'node:https';
      export function downloadAudio(url: string) {
        return https.get(url);
      }
    `,
  });
  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  const outbound = findings.find((finding) => finding.ruleId === 'TW-AST005');
  assert.equal(outbound?.evidence[0]?.file, 'src/services/audio.ts');
  assert.ok(outbound?.evidence.some((item) => item.file === 'src/routes/video.ts'));
});

test('AST retains nested option taint through Object.assign across files', () => {
  const snapshot = snapshotFromFiles({
    'src/routes/video.ts': `
      import { processVideo } from '../services/video-processing';
      app.post('/video', async (req, res) => {
        await processVideo(req.body.options);
        res.send({ ok: true });
      });
    `,
    'src/services/video-processing.ts': `
      import { downloadAudioIfNeeded } from './audio';
      export async function processVideo(options: unknown) {
        const customOptions = Object.assign({
          audio: { customUrl: 'https://media.example.test/default.mp3' },
        }, options);
        await downloadAudioIfNeeded(customOptions.audio);
      }
    `,
    'src/services/audio.ts': `
      import https from 'node:https';
      export function downloadAudioIfNeeded(audio: { customUrl: string }) {
        return https.get(audio.customUrl);
      }
    `,
  });
  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  const outbound = findings.find((finding) => finding.ruleId === 'TW-AST005');
  assert.equal(outbound?.evidence[0]?.file, 'src/services/audio.ts');
  assert.ok(outbound?.evidence.some((item) => item.file === 'src/routes/video.ts'));
});

test('server-owned Object.assign options avoid outbound flow candidates', () => {
  const ids = astRuleIds(`
    import https from 'node:https';
    export async function POST(request: Request) {
      await request.json();
      const customOptions = Object.assign({}, {
        audio: { customUrl: 'https://media.example.test/default.mp3' },
      });
      return https.get(customOptions.audio.customUrl);
    }
  `);
  assert.ok(!ids.includes('TW-AST005'));
});

test('AST retains taint through native object and URL transformations', () => {
  const ids = astRuleIds(`
    import https from 'node:https';
    export async function POST(request: Request) {
      const body = await request.json();
      const spread = { ...body.options };
      const { destination } = spread;
      const cloned = structuredClone({ destination });
      const rebuilt = Object.fromEntries(Object.entries(cloned));
      const target = new URL(rebuilt.destination);
      return https.get(target.href);
    }
  `);
  assert.ok(ids.includes('TW-AST005'));
});

test('AST retains taint through array transformations', () => {
  const ids = astRuleIds(`
    import https from 'node:https';
    export async function POST(request: Request) {
      const body = await request.json();
      const urls = Array.from(body.urls)
        .filter(Boolean)
        .map((url) => url.trim());
      return https.get(urls.at(0));
    }
  `);
  assert.ok(ids.includes('TW-AST005'));
});

test('native transformations that replace input with fixed URLs remain safe', () => {
  const ids = astRuleIds(`
    import https from 'node:https';
    export async function POST(request: Request) {
      const body = await request.json();
      const urls = body.urls.map(() => 'https://media.example.test/default.mp3');
      const copied = Object.fromEntries([['url', urls.at(0)]]);
      return https.get(copied.url);
    }
  `);
  assert.ok(!ids.includes('TW-AST005'));
});

test('fixed process arguments, contained paths, and literal regexes avoid flow candidates', () => {
  const ids = astRuleIds(`
    export async function POST(request: Request) {
      const body = await request.json();
      assertSafeCommand(body.ref);
      execFile('/usr/bin/git', ['show', body.ref], { shell: false });
      const name = basename(body.path);
      await fs.readFile(name);
      return new RegExp('^[a-z]+$').test(body.value);
    }
  `);
  assert.ok(!ids.includes('TW-AST011'));
  assert.ok(!ids.includes('TW-AST012'));
  assert.ok(!ids.includes('TW-AST013'));
});

test('RegExp exec is not treated as operating-system process execution', () => {
  const ids = astRuleIds(`
    export async function POST(request: Request) {
      const body = await request.json();
      const literal = /^(localhost|127\\.0\\.0\\.1)$/.exec(body.host);
      const constructed = new RegExp('^[a-z]+$').exec(body.name);
      return Response.json({ literal, constructed });
    }
  `);
  assert.ok(!ids.includes('TW-AST011'));
});

test('AST identifies weak digests, dynamic property writes, and whole-object mutations', () => {
  const ids = astRuleIds(`
    export async function PATCH(request: Request) {
      const body = await request.json();
      const digest = crypto.createHash('sha1').update(body.token).digest('hex');
      const result = {};
      result[body.key] = body.value;
      await prisma.user.update({ where: { id: body.id }, data: body });
      return Response.json({ digest });
    }
  `);
  assert.ok(ids.includes('TW-AST015'));
  assert.ok(ids.includes('TW-AST016'));
  assert.ok(ids.includes('TW-AST018'));
});

test('strong digests, fixed keys, selected fields, and schema parsing avoid new candidates', () => {
  const ids = astRuleIds(`
    export async function PATCH(request: Request) {
      const body = await request.json();
      const parsed = UserPatch.safeParse(body);
      if (!parsed.success) return Response.json({ error: 'invalid' }, { status: 400 });
      const digest = crypto.createHash('sha256').update(parsed.data.token).digest('hex');
      const result = { name: parsed.data.name };
      await prisma.user.update({
        where: { id: parsed.data.id },
        data: { name: parsed.data.name },
      });
      return Response.json({ digest, result });
    }
  `);
  assert.ok(!ids.includes('TW-AST015'));
  assert.ok(!ids.includes('TW-AST016'));
  assert.ok(!ids.includes('TW-AST018'));
});

test('custom validation and server-bound scope avoid mass-assignment noise', () => {
  const validatedIds = astRuleIds(`
    export async function POST(request: Request) {
      const body = await request.json();
      validateCompositionQuality(body);
      await prisma.page.create({ data: body });
      return Response.json({ ok: true });
    }
  `);
  assert.ok(!validatedIds.includes('TW-AST018'));

  const scopedIds = astRuleIds(`
    export async function POST(
      request: Request,
      { params }: { params: Promise<{ id: string }> },
    ) {
      const { id } = await params;
      const page = await buildStaticPage();
      await prisma.page.create({
        data: { websiteId: id, path: page.path, title: page.title },
      });
      return Response.json({ ok: true });
    }
  `);
  assert.ok(!scopedIds.includes('TW-AST018'));

  const unvalidatedIds = astRuleIds(`
    export async function POST(request: Request) {
      const body = await request.json();
      await validateOnboardingAreaSelection({ payload: body });
      revalidatePath(body.path);
      await prisma.page.create({ data: body });
      return Response.json({ ok: true });
    }
  `);
  assert.ok(unvalidatedIds.includes('TW-AST018'));
});

test('AST distinguishes whole-object NoSQL queries from allowlisted filters', () => {
  const vulnerable = astRuleIds(`
    export async function POST(request: Request) {
      const filter = await request.json();
      return mongo.collection.find(filter);
    }
  `);
  assert.ok(vulnerable.includes('TW-AST017'));

  const safe = astRuleIds(`
    export async function POST(request: Request) {
      const body = await request.json();
      const parsed = SearchInput.parse(body);
      return mongo.collection.find({ email: parsed.email });
    }
  `);
  assert.ok(!safe.includes('TW-AST017'));
});

test('AST propagates request data through bounded cross-file function calls', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/run/route.ts': `
      import { runTask } from '@/lib/tasks';
      export async function POST(request: Request) {
        const body = await request.json();
        return runTask(body.command, body.path);
      }
    `,
    'src/lib/tasks.ts': `
      export function runTask(command: string, file: string) {
        exec(command);
        return fs.readFile(file);
      }
    `,
  });
  const findings = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  const command = findings.find((finding) => finding.ruleId === 'TW-AST011');
  const traversal = findings.find((finding) => finding.ruleId === 'TW-AST012');
  assert.equal(command?.evidence[0]?.file, 'src/lib/tasks.ts');
  assert.equal(traversal?.evidence[0]?.file, 'src/lib/tasks.ts');
  assert.ok(command?.evidence.some((item) => item.file === 'src/app/api/run/route.ts'));
});

test('tRPC mutations participate in authentication and object-scope review', () => {
  const publicSnapshot = snapshotOf(
    `export const remove = publicProcedure.input(Input).mutation(async ({ input }) => {
      return db.user.delete({ where: { id: input.id } });
    });`,
    'src/server/router.ts',
  );
  const publicIds = scanAstSecurity(
    publicSnapshot,
    profileProject(publicSnapshot).profile,
  ).findings.map((finding) => finding.ruleId);
  assert.ok(publicIds.includes('TW-AST001'));

  const protectedSnapshot = snapshotOf(
    `export const remove = protectedProcedure.input(Input).mutation(async ({ input, ctx }) => {
      return db.user.delete({ where: { id: input.id } });
    });`,
    'src/server/router.ts',
  );
  const protectedIds = scanAstSecurity(
    protectedSnapshot,
    profileProject(protectedSnapshot).profile,
  ).findings.map((finding) => finding.ruleId);
  assert.ok(!protectedIds.includes('TW-AST001'));
  assert.ok(protectedIds.includes('TW-AST003'));

  const scopedSnapshot = snapshotOf(
    `export const remove = protectedProcedure.input(Input).mutation(async ({ input, ctx }) => {
      return db.user.delete({ where: { id: input.id, userId: ctx.user.id } });
    });`,
    'src/server/router.ts',
  );
  const scopedIds = scanAstSecurity(
    scopedSnapshot,
    profileProject(scopedSnapshot).profile,
  ).findings.map((finding) => finding.ruleId);
  assert.ok(!scopedIds.includes('TW-AST001'));
  assert.ok(!scopedIds.includes('TW-AST003'));
});

test('a decisive AST flow replaces the same-location broad raw SQL pattern', () => {
  const snapshot = snapshotOf(
    `export async function POST(request: Request) {
      requireUser();
      const body = await request.json();
      return db.$queryRawUnsafe(\`SELECT * FROM tasks WHERE id = '${'${body.id}'}'\`);
    }`,
    'src/app/api/tasks/route.ts',
  );
  const ast = scanAstSecurity(snapshot, profileProject(snapshot).profile).findings;
  const reconciled = preferStructuralFindings([...scanPatterns(snapshot), ...ast]);
  assert.ok(reconciled.some((finding) => finding.ruleId === 'TW-AST004'));
  assert.ok(!reconciled.some((finding) => finding.ruleId === 'TW-001'));
});

test('the structural profile replaces generic ID lookup hotspots for parsed files', () => {
  const snapshot = snapshotOf(
    'export async function load(id: string) { return db.project.findUnique({ where: { id } }); }',
    'src/data.ts',
  );
  const profile = profileProject(snapshot).profile;
  const broad = scanPatterns(snapshot);
  assert.ok(broad.some((finding) => finding.ruleId === 'TW-004'));
  assert.ok(
    !preferStructuralFindings(broad, profile).some((finding) => finding.ruleId === 'TW-004'),
  );
  assert.ok(preferStructuralFindings(broad).some((finding) => finding.ruleId === 'TW-004'));
});
