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

  const trustedAccess = findingsFor(`
    export async function PATCH(request: Request) {
      const trace = resolveRequestTrace(request);
      const access = await resolveNotificationsViewerAccess(trace);
      return prisma.notification.update({
        where: { id: 'notification-1' },
        data: { userId: access.userId, readAt: new Date() },
        include: { organization: { select: { id: true } } }
      });
    }
  `);
  assert.ok(!trustedAccess.some((finding) => finding.ruleId === 'TW-SAAS002'));

  const includedRelation = findingsFor(`
    export async function POST(request: Request) {
      const body = await request.json();
      return prisma.website.create({
        data: { organizationId: body.organizationId },
        include: { organization: { select: { id: true } } }
      });
    }
  `).filter((finding) => finding.ruleId === 'TW-SAAS002');
  assert.equal(includedRelation.length, 1);
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

  const inertExample = findingsFor(
    'export const fixture = { code: "const resetToken = Date.now().toString() + Math.random();" };',
  );
  assert.ok(!inertExample.some((finding) => finding.ruleId === 'TW-SAAS003'));
});

test('SaaS error rule reports caught internals but accepts a stable public error', () => {
  const vulnerable = findingsFor(`
    export async function POST() {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) { return Response.json({ error: error.message, stack: error.stack }); }
    }
  `);
  assert.ok(vulnerable.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const aliased = findingsFor(`
    export async function POST(request: Request) {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        return Response.json({ status: 500, message });
      }
    }
  `);
  assert.ok(aliased.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const aliasedResponseWrapper = findingsFor(`
    export async function POST(request: Request) {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        return apiLegacyError({ status: 500, message });
      }
    }
  `);
  assert.ok(aliasedResponseWrapper.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const returnedErrorWrapper = findingsFor(`
    export async function POST() {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) {
        return respondError('internal_error', 'Unexpected internal error', {
          reason: error instanceof Error ? error.message : String(error),
        });
      }
    }
  `);
  assert.ok(returnedErrorWrapper.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const stableErrorWrapper = findingsFor(`
    export async function POST() {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) {
        logger.error({ error }, 'invoice failed');
        return respondError('internal_error', 'Unexpected internal error');
      }
    }
  `);
  assert.ok(!stableErrorWrapper.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const derivedStatus = findingsFor(`
    export async function POST(request: Request) {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) {
        const status = error instanceof KnownPublicError ? 400 : 500;
        return Response.json({ code: 'INVOICE_FAILED' }, { status });
      }
    }
  `);
  assert.ok(!derivedStatus.some((finding) => finding.ruleId === 'TW-SAAS004'));

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

  const stableErrorField = findingsFor(`
    export async function POST() {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch { return Response.json({ error: 'INVOICE_FAILED' }, { status: 500 }); }
    }
  `);
  assert.ok(!stableErrorField.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const predicateOnly = findingsFor(`
    export async function POST() {
      try { return Response.json(await database.invoice.create({ data: {} })); }
      catch (error) {
        const message = error instanceof Error ? error.message : '';
        return Response.json({
          error: message.includes('UNIQUE') ? 'INVOICE_EXISTS' : 'INVOICE_FAILED',
        });
      }
    }
  `);
  assert.ok(!predicateOnly.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const validationDetails = findingsFor(`
    export async function POST(request: Request) {
      try {
        const body = await request.json();
        return Response.json(await database.invoice.create({ data: body }));
      } catch (error) {
        if (error instanceof z.ZodError) {
          return Response.json({ error: 'VALIDATION_FAILED', details: error.errors }, { status: 400 });
        }
        return Response.json({ error: error.message }, { status: 500 });
      }
    }
  `).filter((finding) => finding.ruleId === 'TW-SAAS004');
  assert.equal(validationDetails.length, 1);
});

test('SaaS error rule proves imported normalizers return only fixed public codes', () => {
  const safeSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      import { resolvePublicError } from '../../../lib/errors';
      export async function POST() {
        try { return Response.json(await database.invoice.create({ data: {} })); }
        catch (error) {
          return Response.json({ error: resolvePublicError(error) }, { status: 500 });
        }
      }
    `,
    'src/lib/errors.ts': `
      export function resolvePublicError(error: unknown) {
        if (error instanceof Error && error.message.includes('missing')) {
          return 'NOT_FOUND' as const;
        }
        return 'INTERNAL_ERROR';
      }
    `,
  });
  const safe = scanSaasSecurity(safeSnapshot, profileProject(safeSnapshot).profile).findings;
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const unsafeSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      import { resolvePublicError } from '../../../lib/errors';
      export async function POST() {
        try { return Response.json(await database.invoice.create({ data: {} })); }
        catch (error) {
          return Response.json({ error: resolvePublicError(error) }, { status: 500 });
        }
      }
    `,
    'src/lib/errors.ts': `
      export function resolvePublicError(error: unknown) {
        if (error instanceof Error) return error.message;
        return 'INTERNAL_ERROR';
      }
    `,
  });
  const unsafe = scanSaasSecurity(unsafeSnapshot, profileProject(unsafeSnapshot).profile).findings;
  assert.ok(unsafe.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const structuredSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      import { reportFailure, resolveFailure } from '../../../lib/errors';
      export async function POST() {
        try { return Response.json(await database.invoice.create({ data: {} })); }
        catch (error) {
          const failure = reportFailure('invoice', error);
          const { code, status } = resolveFailure(error);
          return Response.json({ error: code, ...failure }, { status });
        }
      }
    `,
    'src/lib/errors.ts': `
      export function reportFailure(operation: string, error: unknown) {
        const failureId = randomUUID();
        const errorName = error instanceof Error ? error.name : 'UnknownError';
        logger.error({ operation, errorName, failureId });
        return { failureId };
      }
      export function resolveFailure(error: unknown) {
        const message = normalizeError(error);
        const status = message.includes('not configured') ? 503 : 500;
        return { code: status === 503 ? 'NOT_CONFIGURED' : 'UNAVAILABLE', status };
      }
    `,
  });
  const structured = scanSaasSecurity(
    structuredSnapshot,
    profileProject(structuredSnapshot).profile,
  ).findings;
  assert.ok(!structured.some((finding) => finding.ruleId === 'TW-SAAS004'));
});

test('SaaS error rule proves static call-site message allowlists', () => {
  const safeSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      import { publicMessage } from '../../../lib/errors';
      export async function POST() {
        try { return Response.json(await database.invoice.create({ data: {} })); }
        catch (error) {
          return Response.json({
            error: publicMessage(error, ['NOT_FOUND', 'CONFLICT'], 'INTERNAL_ERROR'),
          });
        }
      }
    `,
    'src/lib/errors.ts': `
      export function publicMessage(error: unknown, allowed: readonly string[], fallback: string) {
        if (!(error instanceof Error)) return fallback;
        return allowed.includes(error.message) ? error.message : fallback;
      }
    `,
  });
  const safe = scanSaasSecurity(safeSnapshot, profileProject(safeSnapshot).profile).findings;
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const unsafeSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      import { publicMessage } from '../../../lib/errors';
      export async function POST(request: Request) {
        const body = await request.json();
        try { return Response.json(await database.invoice.create({ data: {} })); }
        catch (error) {
          return Response.json({ error: publicMessage(error, body.allowed, 'INTERNAL_ERROR') });
        }
      }
    `,
    'src/lib/errors.ts': `
      export function publicMessage(error: unknown, allowed: readonly string[], fallback: string) {
        if (!(error instanceof Error)) return fallback;
        return allowed.includes(error.message) ? error.message : fallback;
      }
    `,
  });
  const unsafe = scanSaasSecurity(unsafeSnapshot, profileProject(unsafeSnapshot).profile).findings;
  assert.ok(unsafe.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const stackSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      import { DomainError, fail } from '../../../lib/errors';
      export async function POST() {
        try { fail(); return Response.json({ ok: true }); }
        catch (error) {
          if (error instanceof DomainError) return Response.json({ stack: error.stack });
          throw error;
        }
      }
    `,
    'src/lib/errors.ts': `
      export class DomainError extends Error {
        constructor(message: string) { super(message); this.name = 'DomainError'; }
      }
      export function fail() { throw new DomainError('INVALID_OPERATION'); }
    `,
  });
  const stack = scanSaasSecurity(stackSnapshot, profileProject(stackSnapshot).profile).findings;
  assert.ok(stack.some((finding) => finding.ruleId === 'TW-SAAS004'));
});

test('SaaS error rule proves custom classes are constructed with fixed messages', () => {
  const safeSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      import { DomainError, fail } from '../../../lib/errors';
      export async function POST() {
        try { fail(); return Response.json({ ok: true }); }
        catch (error) {
          if (error instanceof DomainError) return Response.json({ error: error.message });
          throw error;
        }
      }
    `,
    'src/lib/errors.ts': `
      export class DomainError extends Error {
        constructor(message: string) { super(message); this.name = 'DomainError'; }
      }
      export function fail() { throw new DomainError('INVALID_OPERATION'); }
    `,
  });
  const safe = scanSaasSecurity(safeSnapshot, profileProject(safeSnapshot).profile).findings;
  assert.ok(!safe.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const unsafeSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      import { DomainError, fail } from '../../../lib/errors';
      export async function POST(request: Request) {
        try { fail((await request.json()).message); return Response.json({ ok: true }); }
        catch (error) {
          if (error instanceof DomainError) return Response.json({ error: error.message });
          throw error;
        }
      }
    `,
    'src/lib/errors.ts': `
      export class DomainError extends Error {
        constructor(message: string) { super(message); this.name = 'DomainError'; }
      }
      export function fail(message: string) { throw new DomainError(message); }
    `,
  });
  const unsafe = scanSaasSecurity(unsafeSnapshot, profileProject(unsafeSnapshot).profile).findings;
  assert.ok(unsafe.some((finding) => finding.ruleId === 'TW-SAAS004'));

  const mixedConstructorSnapshot = snapshotFromFiles({
    'src/app/api/example/route.ts': `
      class DomainError extends Error {
        constructor(message: string, unsafeMessage: string, unsafe: boolean) {
          if (unsafe) super(unsafeMessage); else super(message);
        }
      }
      export async function POST(request: Request) {
        try { throw new DomainError('INVALID_OPERATION', request.url, true); }
        catch (error) {
          if (error instanceof DomainError) return Response.json({ error: error.message });
          throw error;
        }
      }
    `,
  });
  const mixedConstructor = scanSaasSecurity(
    mixedConstructorSnapshot,
    profileProject(mixedConstructorSnapshot).profile,
  ).findings;
  assert.ok(mixedConstructor.some((finding) => finding.ruleId === 'TW-SAAS004'));
});

test('custom SaaS vocabulary is applied without executable configuration', () => {
  const snapshot = snapshotFromFiles({
    'codebasescan.config.json': JSON.stringify({
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
