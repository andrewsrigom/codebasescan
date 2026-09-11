import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanNextSecurity } from '../../src/scanners/next-security.ts';
import { snapshotFromFiles, snapshotOf } from '../helpers.ts';

function scan(content: string, file = 'src/app/api/accounts/[accountId]/route.ts') {
  const snapshot = snapshotOf(content, file);
  return scanNextSecurity(snapshot, profileProject(snapshot).profile);
}

test('Next.js read rules identify missing authentication and resource scope', () => {
  const result = scan(`
    export async function GET(_request: Request, { params }) {
      return Response.json(await db.account.findUnique({ where: { id: params.accountId } }));
    }
  `);
  const ids = new Set(result.findings.map((finding) => finding.ruleId));
  assert.ok(ids.has('TW-NEXT001'));
  assert.ok(ids.has('TW-NEXT002'));
});

test('applicable middleware and owner scope protect a dynamic read route', () => {
  const snapshot = snapshotFromFiles({
    'src/middleware.ts': `
      export async function middleware() { return requireUser(); }
      export const config = { matcher: ['/api/accounts/:path*'] };
    `,
    'src/app/api/accounts/[accountId]/route.ts': `
      export async function GET(_request: Request, { params }) {
        const user = await requireUser();
        return Response.json(await db.account.findFirst({
          where: { id: params.accountId, ownerId: user.id },
        }));
      }
    `,
  });
  const result = scanNextSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT001'));
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT002'));
});

test('middleware data access is not attributed to a read route', () => {
  const snapshot = snapshotFromFiles({
    'src/middleware.ts': `
      export async function middleware(request) {
        await db.website.findFirst({ where: { host: request.headers.get('host') } });
        return NextResponse.next();
      }
      export const config = { matcher: ['/api/:path*'] };
    `,
    'src/app/api/health/route.ts': `
      export async function GET() { return Response.json({ ok: true }); }
    `,
  });
  const findings = scanNextSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-NEXT001'));
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-NEXT002'));
});

test('a scoped service helper protects a dynamic read route', () => {
  const result = scan(`
    export async function GET(_request: Request, { params }) {
      const session = await getAppSession();
      return Response.json(await getAccountForUser(session.user.id, params.accountId));
    }
  `);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT001'));
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT002'));
});

test('Next.js cache rule distinguishes request state from explicit cached input', () => {
  const vulnerableSnapshot = snapshotFromFiles({
    'package.json': '{"dependencies":{"next":"16.0.0"}}',
    'src/app/dashboard/actions.ts': `
      import { cookies } from 'next/headers';
      export async function getDashboard() {
        'use cache';
        const session = cookies().get('session');
        return db.dashboard.findMany({ where: { session } });
      }
    `,
  });
  const vulnerable = scanNextSecurity(
    vulnerableSnapshot,
    profileProject(vulnerableSnapshot).profile,
  );
  assert.ok(vulnerable.findings.some((finding) => finding.ruleId === 'TW-NEXT003'));

  const safeSnapshot = snapshotFromFiles({
    'package.json': '{"dependencies":{"next":"16.0.0"}}',
    'src/app/catalog/actions.ts': `
      export async function getCatalog(tenantId: string) {
        'use cache';
        return db.product.findMany({ where: { tenantId, published: true } });
      }
    `,
  });
  const safe = scanNextSecurity(safeSnapshot, profileProject(safeSnapshot).profile);
  assert.ok(!safe.findings.some((finding) => finding.ruleId === 'TW-NEXT003'));
});

test('Next.js public environment rule catches sensitive-shaped variables', () => {
  const snapshot = snapshotFromFiles({
    'package.json': '{"dependencies":{"next":"16.0.0"}}',
    'src/config.ts': `export const clientConfig = process.env.NEXT_PUBLIC_SERVICE_ROLE_TOKEN;`,
  });
  const result = scanNextSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-NEXT004'));
});

test('authenticated routes do not declare shared response caching', () => {
  const result = scan(
    `
      export async function GET() {
        await requireUser();
        const response = Response.json(await db.account.findMany());
        response.headers.set('Cache-Control', 'public, s-maxage=300');
        return response;
      }
    `,
    'src/app/api/accounts/route.ts',
  );
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-NEXT005'));
});

test('Next.js mutation rule requires recognized validation before sensitive work', () => {
  const vulnerable = scan(
    `
      export async function POST(request: Request) {
        await requireUser();
        const body = (await request.json()) as Record<string, unknown>;
        return Response.json(await db.account.create({ data: body }));
      }
    `,
    'src/app/api/accounts/route.ts',
  );
  assert.ok(vulnerable.findings.some((finding) => finding.ruleId === 'TW-NEXT006'));

  const safe = scan(
    `
      export async function POST(request: Request) {
        await requireUser();
        const body = accountSchema.parse(await request.json());
        return Response.json(await db.account.create({ data: body }));
      }
    `,
    'src/app/api/accounts/route.ts',
  );
  assert.ok(!safe.findings.some((finding) => finding.ruleId === 'TW-NEXT006'));
});

test('Next.js mutation rule does not treat a database read as a state change', () => {
  const result = scan(
    `
      export async function POST() {
        await requireUser();
        return Response.json(await db.project.findUnique({ where: { id: 'fixed-id' } }));
      }
    `,
    'src/app/api/project/route.ts',
  );
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT006'));
});

test('Next.js mutation rule does not require a body schema for a parameter-only delete', () => {
  const snapshot = snapshotOf(
    `
      export async function DELETE(_request: Request, { params }: { params: Promise<{ id: string }> }) {
        const { id } = await params;
        await db.project.delete({ where: { id } });
        return Response.json({ ok: true });
      }
    `,
    'src/app/api/projects/[id]/route.ts',
  );
  snapshot.files.push({
    path: 'package.json',
    scope: 'runtime',
    content: JSON.stringify({ dependencies: { next: '16.0.0' } }),
    digest: 'manifest',
    bytes: 47,
  });
  const result = scanNextSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT006'));
});

test('Next.js mutation rule recognizes bounded inline payload validation', () => {
  const snapshot = snapshotOf(
    `
      export async function POST(request: Request) {
        const body = await request.json();
        if (typeof body.name !== 'string' || body.name.length > 120) {
          return Response.json({ error: 'invalid name' }, { status: 400 });
        }
        await db.project.create({ data: { name: body.name } });
        return Response.json({ ok: true });
      }
    `,
    'src/app/api/projects/route.ts',
  );
  snapshot.files.push({
    path: 'package.json',
    scope: 'runtime',
    content: JSON.stringify({ dependencies: { next: '16.0.0' } }),
    digest: 'manifest',
    bytes: 47,
  });
  const result = scanNextSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT006'));
});

test('Next.js mutation rule follows Server Action parameter normalization', () => {
  const snapshot = snapshotFromFiles({
    'package.json': '{"dependencies":{"next":"16.0.0"}}',
    'src/app/actions.ts': `
      'use server';
      function normalizeField(value: FormDataEntryValue | null): string {
        return typeof value === 'string' ? value.trim() : '';
      }
      export async function deleteProjectAction(formData: FormData) {
        const projectId = normalizeField(formData.get('projectId'));
        if (!projectId) throw new Error('Missing project id');
        await db.project.delete({ where: { id: projectId } });
      }
    `,
  });
  const result = scanNextSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT006'));
});

test('Next.js rules recognize descriptive authentication and validation wrappers', () => {
  const result = scan(
    `
      export async function POST(request: Request) {
        await authenticateDeveloperApiRequest(request);
        const input = parseBoundedAccountInput(request);
        return Response.json(await db.account.update({ data: input }));
      }
    `,
    'src/app/api/accounts/route.ts',
  );
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-NEXT006'));
});

test('Next.js response rule catches sensitive-shaped response fields', () => {
  const result = scan(
    `
      export async function POST() {
        return Response.json({ accessToken: await issueToken() });
      }
    `,
    'src/app/api/session/route.ts',
  );
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-NEXT007'));
});

test('non-Next.js source skips the framework-specific scanner', () => {
  const snapshot = snapshotOf(`export const value = process.env.NEXT_PUBLIC_API_URL;`);
  const result = scanNextSecurity(snapshot, profileProject(snapshot).profile);
  assert.equal(result.run.status, 'skipped');
  assert.deepEqual(result.findings, []);
});
