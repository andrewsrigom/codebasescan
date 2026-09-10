import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanWebhookContract } from '../../src/scanners/webhook-contract.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('webhook contract connects endpoint, verification, and normalized event vocabulary', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/billing/webhook/route.ts': `
import { parseBillingWebhookEvent } from '../../../../lib/billing';
export async function POST(request: Request) {
  const event = await parseBillingWebhookEvent(await request.text());
  switch (event.type) {
    case 'checkout.completed': return Response.json({ ok: true });
    case 'checkout.failed': return Response.json({ ok: false });
  }
}
`,
    'src/lib/billing.ts': `
export function parseBillingWebhookEvent(rawBody: string) {
  const event = stripe.webhooks.constructEvent(rawBody, signature, secret);
  if (event.type === 'checkout.session.completed') return { type: 'checkout.completed' };
  return { type: 'checkout.failed' };
}
`,
  });
  const profile = profileProject(snapshot).profile;
  const result = scanWebhookContract(snapshot, profile);
  assert.equal(result.analysis.status, 'complete');
  assert.equal(result.analysis.summary.endpoints, 1);
  assert.equal(result.analysis.summary.verifiedEndpoints, 1);
  assert.equal(result.analysis.summary.matchedEvents, 2);
  assert.equal(result.analysis.summary.externalConsumerBoundaries, 1);
  assert.equal(result.analysis.endpoints[0]?.verification, 'evidenced');
  assert.ok(result.analysis.endpoints[0]?.callEdgeIds.length);
  assert.ok(
    result.analysis.events.some(
      (event) => event.normalizedEvent === 'checkout.completed' && event.status === 'matched-local',
    ),
  );
  assert.equal(result.run.findings, 0);
});

test('unpaired webhook event names are external boundaries rather than mismatch findings', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/provider/webhook/route.ts': `
export async function POST(request: Request) {
  const event = await request.json();
  if (event.type === 'invoice.paid') return Response.json({ received: true });
}
`,
    'src/delivery.ts': `
export function deliverWebhook() {
  return webhookClient.send({ event: 'account.created', payload: {} });
}
`,
  });
  const result = scanWebhookContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.summary.externalConsumerBoundaries, 1);
  assert.equal(result.analysis.summary.externalProducerBoundaries, 1);
  assert.equal(result.analysis.summary.matchedEvents, 0);
  assert.match(result.analysis.limitations.join(' '), /not defects/i);
  assert.equal(result.run.findings, 0);
});

test('callback routes without verification evidence and projects without webhooks stay honest', () => {
  const callback = snapshotFromFiles({
    'src/app/api/oauth/callback/route.ts':
      'export async function GET() { return Response.json({ ok: true }); }',
  });
  const callbackResult = scanWebhookContract(callback, profileProject(callback).profile);
  assert.equal(callbackResult.analysis.status, 'unsupported');
  assert.equal(callbackResult.analysis.summary.endpoints, 0);
  assert.equal(callbackResult.run.status, 'skipped');

  const webhook = snapshotFromFiles({
    'src/app/api/custom/webhook/route.ts':
      'export async function POST() { return Response.json({ ok: true }); }',
  });
  const webhookResult = scanWebhookContract(webhook, profileProject(webhook).profile);
  assert.equal(webhookResult.analysis.status, 'complete');
  assert.equal(webhookResult.analysis.endpoints[0]?.verification, 'unverified');
  assert.match(webhookResult.analysis.limitations.join(' '), /does not prove/i);
});

test('malformed reachable source makes webhook contract coverage partial', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/custom/webhook/route.ts': `
export async function POST() {
  const event = broken(;
  if (event.type === 'broken') return Response.json({ ok: true });
}
`,
  });
  const result = scanWebhookContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.status, 'partial');
  assert.equal(result.analysis.parseFailures, 1);
});
