import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanTestEvidence } from '../../src/scanners/test-evidence.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('test evidence maps direct and transitive imports to critical source files', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/account/route.ts': `
      import { updateAccount } from '../../../services/account';
      export async function POST() { return updateAccount(); }
    `,
    'src/services/account.ts': `
      export async function updateAccount() { return database.account.update({ data: {} }); }
    `,
    'tests/account.test.ts': `
      import { POST } from '../src/app/api/account/route';
      void POST;
    `,
  });
  snapshot.files.find((file) => file.path === 'tests/account.test.ts')!.scope = 'test';
  const profile = profileProject(snapshot).profile;
  const result = scanTestEvidence(snapshot, profile);
  const route = result.analysis.targets.find(
    (target) => target.file === 'src/app/api/account/route.ts',
  );
  const service = result.analysis.targets.find(
    (target) => target.file === 'src/services/account.ts',
  );
  assert.equal(route?.relatedTests[0]?.relation, 'direct-import');
  assert.equal(service?.relatedTests[0]?.relation, 'transitive-import');
  assert.equal(service?.relatedTests[0]?.depth, 2);
  assert.equal(result.analysis.withoutRelatedTests, 0);
  assert.equal(result.run.findings, 0);
});

test('missing related imports remain explicit without becoming a vulnerability', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/admin/route.ts': `
      export async function DELETE() { return database.user.delete({ where: { id: '1' } }); }
    `,
    'tests/unrelated.test.ts': `export const unrelated = true;`,
  });
  snapshot.files.find((file) => file.path === 'tests/unrelated.test.ts')!.scope = 'test';
  const result = scanTestEvidence(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.withoutRelatedTests, 1);
  assert.equal(result.analysis.targets[0]?.status, 'not-observed');
  assert.match(result.analysis.limitations.at(-1) ?? '', /not that the code is untested/i);
});

test('black-box URL tests are not falsely attributed to route source', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/orders/route.ts': `export async function POST() { return database.order.create({ data: {} }); }`,
    'e2e/orders.spec.ts': `test('order', async ({ page }) => page.goto('/api/orders'));`,
  });
  snapshot.files.find((file) => file.path === 'e2e/orders.spec.ts')!.scope = 'test';
  const result = scanTestEvidence(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.withRelatedTests, 0);
  assert.equal(result.analysis.withoutRelatedTests, 1);
});

test('unresolved source imports keep relationship coverage partial', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/orders/route.ts': `
      import { missing } from '@/missing';
      export async function POST() { missing(); return Response.json({ ok: true }); }
    `,
  });
  const result = scanTestEvidence(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.unresolvedImports, 1);
  assert.equal(result.analysis.status, 'partial');
  assert.equal(result.analysis.truncated, false);
});
