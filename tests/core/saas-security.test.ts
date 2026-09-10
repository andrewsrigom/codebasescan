import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanSaasSecurity } from '../../src/scanners/saas-security.ts';
import { snapshotFromFiles, snapshotOf } from '../helpers.ts';

function findingsFor(source: string) {
  const snapshot = snapshotOf(source, 'src/app/api/example/route.ts');
  return scanSaasSecurity(snapshot, profileProject(snapshot).profile).findings;
}

test('SaaS billing rule distinguishes client prices from a server catalog lookup', () => {
  const vulnerable = findingsFor(`
    export async function POST(request: Request) {
      const body = await request.json();
      return stripe.checkout.sessions.create({ line_items: [{ price: body.priceId }] });
    }
  `);
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS001'));

  const safe = findingsFor(`
    const PRICE_IDS = { starter: 'price_server_owned' };
    export async function POST(request: Request) {
      const body = await request.json();
      return stripe.checkout.sessions.create({ line_items: [{ price: PRICE_IDS[body.plan] }] });
    }
  `);
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS001'));
});

test('SaaS request-flow rules ignore similarly named internal parameters and scripts', () => {
  const snapshot = snapshotFromFiles({
    'src/billing.ts': `
      export async function createProviderPrice(input) {
        logger.info({ email: input.email }, 'catalog import');
        return stripe.prices.create({ unit_amount: input.amount });
      }
    `,
    'scripts/import-products.mjs': `
      async function importProducts(body) {
        return stripe.prices.create({ unit_amount: body.amount });
      }
    `,
  });
  const findings = scanSaasSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-SAAS001'));
  assert.ok(!findings.some((finding) => finding.ruleId === 'TW-SAAS005'));
});

test('SaaS assignment rule distinguishes request ownership from session ownership', () => {
  const vulnerable = findingsFor(`
    export async function PATCH(request: Request) {
      const { teamId, role } = await request.json();
      return prisma.member.update({ where: { teamId }, data: { role } });
    }
  `);
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS002'));

  const safe = findingsFor(`
    export async function PATCH(request: Request) {
      const session = await requireSession();
      const body = await request.json();
      return prisma.member.update({
        where: { teamId: session.user.teamId },
        data: { displayName: body.displayName }
      });
    }
  `);
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS002'));
});

test('SaaS token rule reports predictable entropy but accepts crypto randomness', () => {
  const vulnerable = findingsFor(`
    export async function POST() {
      const resetToken = Date.now().toString() + Math.random();
      return prisma.reset.create({ data: { resetToken } });
    }
  `);
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS003'));

  const safe = findingsFor(`
    import { randomBytes } from 'node:crypto';
    export async function POST() {
      const resetToken = randomBytes(32).toString('hex');
      return prisma.reset.create({ data: { resetToken } });
    }
  `);
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS003'));
});

test('SaaS error rule reports caught internals but accepts a stable public error', () => {
  const vulnerable = findingsFor(`
    export async function POST() {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) { return Response.json({ error: error.message, stack: error.stack }); }
    }
  `);
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const safe = findingsFor(`
    export async function POST() {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) {
        logger.error({ error }, 'invoice failed');
        return Response.json({ code: 'INVOICE_FAILED' }, { status: 500 });
      }
    }
  `);
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS004'));
});

test('custom SaaS vocabulary is applied without executable configuration', () => {
  const snapshot = snapshotFromFiles({
    'traceward.config.json': JSON.stringify({
      schemaVersion: 1,
      vocabulary: { roleKeys: ['membershipLevel'] },
    }),
    'src/app/api/member/route.ts': `
      export async function PATCH(request: Request) {
        const body = await request.json();
        return database.member.update({ data: { membershipLevel: body.membershipLevel } });
      }
    `,
  });
  const findings = scanSaasSecurity(snapshot, profileProject(snapshot).profile).findings;
  assert.ok(findings.some((finding) => finding.ruleId === 'TW-SAAS002'));
});

test('SaaS data exposure rules distinguish raw sensitive values from redaction', () => {
  const vulnerable = findingsFor(`
    export async function POST(request: Request) {
      const body = await request.json();
      logger.info({ email: body.email, token: body.token }, 'received');
      const url = new URL('https://example.test/callback');
      url.searchParams.set('token', body.token);
      return Response.json({ ok: true });
    }
  `);
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS005'));
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS006'));

  const safe = findingsFor(`
    export async function POST(request: Request) {
      const body = await request.json();
      logger.info({ emailHash: hash(body.email) }, 'received');
      return fetch('https://example.test/callback', {
        headers: { authorization: 'Bearer ' + body.token }
      });
    }
  `);
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS005'));
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS006'));
});

test('SaaS OAuth rule distinguishes client redirects from an allowlisted lookup', () => {
  const vulnerable = findingsFor(`
    export async function POST(request: Request) {
      const body = await request.json();
      return oauth.authorization.create({ redirect_uri: body.redirectUri });
    }
  `);
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS007'));

  const safe = findingsFor(`
    const REDIRECT_URIS = { app: 'https://app.example.test/callback' };
    export async function POST(request: Request) {
      const body = await request.json();
      return oauth.authorization.create({ redirect_uri: REDIRECT_URIS[body.client] });
    }
  `);
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS007'));
});

test('SaaS recovery rules require hashed tokens and an expiry', () => {
  const vulnerable = findingsFor(`
    export async function POST() {
      const resetToken = crypto.randomUUID();
      return database.passwordReset.create({ data: { resetToken } });
    }
  `);
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS008'));
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS009'));

  const safe = findingsFor(`
    export async function POST() {
      const resetToken = crypto.randomUUID();
      return database.passwordReset.create({
        data: { tokenHash: hash(resetToken), expiresAt: new Date(Date.now() + 900_000) }
      });
    }
  `);
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS008'));
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS009'));
});
