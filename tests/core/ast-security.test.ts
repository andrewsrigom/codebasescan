import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { scanAstSecurity } from '../../src/scanners/ast-security.ts';
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
