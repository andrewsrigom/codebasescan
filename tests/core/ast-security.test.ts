import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { preferStructuralFindings, scanAstSecurity } from '../../src/scanners/ast-security.ts';
import { scanPatterns } from '../../src/scanners/builtin.ts';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import { snapshotOf } from '../helpers.ts';

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

test('recognized two-hop auth, permission, and owner scope avoid AST gap candidates', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/profile-nextjs'));
  const profile = profileProject(snapshot).profile;
  const result = scanAstSecurity(snapshot, profile);
  assert.equal(result.run.status, 'completed');
  assert.deepEqual(result.findings, []);
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
