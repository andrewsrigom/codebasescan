import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { buildSecurityChecklist } from '../../src/domain/checklist.ts';
import { scanAstSecurity } from '../../src/scanners/ast-security.ts';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { captureSnapshot } from '../../src/security/paths.ts';
import type { ScannerRun, Snapshot } from '../../src/domain/types.ts';
import { snapshotOf } from '../helpers.ts';

function skipped(id: string, name = id): ScannerRun {
  return {
    id,
    name,
    status: 'skipped',
    durationMs: 0,
    findings: 0,
    detail: 'Not enabled for checklist test.',
  };
}

function checklistFor(snapshot: Snapshot) {
  const profileResult = profileProject(snapshot);
  const astResult = scanAstSecurity(snapshot, profileResult.profile);
  return buildSecurityChecklist({
    projectProfile: profileResult.profile,
    findings: astResult.findings,
    scanners: [
      profileResult.run,
      astResult.run,
      { ...skipped('posture'), status: 'completed' },
      skipped('gitleaks'),
      skipped('osv'),
      skipped('http-probe'),
    ],
    dependencies: [],
  });
}

test('checklist turns AST findings into explicit gap candidates', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/ast-auth-vulnerable'));
  const checklist = checklistFor(snapshot);
  for (const id of ['TW-CTRL-AUTHN-001', 'TW-CTRL-AUTHZ-001', 'TW-CTRL-AUTHZ-002'])
    assert.equal(checklist.controls.find((control) => control.id === id)?.status, 'GAP_CANDIDATE');
  assert.ok(checklist.summary.GAP_CANDIDATE >= 3);
  assert.ok(
    checklist.controls
      .find((control) => control.id === 'TW-CTRL-AUTHN-001')
      ?.evidence.some((item) => item.kind === 'finding'),
  );
});

test('mapped wrappers and scope can evidence narrow controls without claiming global safety', async () => {
  const snapshot = await captureSnapshot(path.resolve('fixtures/profile-nextjs'));
  const checklist = checklistFor(snapshot);
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-AUTHN-001')?.status,
    'EVIDENCED',
  );
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-AUTHZ-001')?.status,
    'EVIDENCED',
  );
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-AUTHZ-002')?.status,
    'EVIDENCED',
  );
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-LOGGING-001')?.status,
    'UNVERIFIED',
  );
});

test('unsupported source remains unverified instead of becoming not applicable or clean', () => {
  const checklist = checklistFor(snapshotOf('{}', 'package.json'));
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-AUTHN-001')?.status,
    'UNVERIFIED',
  );
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-LOGGING-001')?.status,
    'UNVERIFIED',
  );
});

test('dependency and runtime controls reflect completed, failed, and opted-out scanners', () => {
  const dependencies = [
    {
      name: 'fixture',
      requestedVersion: '^1.0.0',
      resolvedVersion: '1.0.1',
      manifest: 'package.json',
      scope: 'runtime' as const,
    },
  ];
  const checklist = buildSecurityChecklist({
    findings: [],
    scanners: [
      { ...skipped('osv'), status: 'completed' },
      { ...skipped('http-probe'), status: 'failed' },
    ],
    dependencies,
  });
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-DEPS-001')?.status,
    'EVIDENCED',
  );
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-RUNTIME-001')?.status,
    'FAILED',
  );
});

test('code-first flow findings become checklist gaps without claiming runtime proof', () => {
  const snapshot = snapshotOf(
    `
      export async function POST(request: Request) {
        requireUser();
        const body = await request.json();
        await db.$queryRawUnsafe(\`SELECT * FROM tasks WHERE name = '${'${body.name}'}'\`);
        const target = body.target;
        await fetch(target);
        const form = await request.formData();
        const file = form.get('file');
        await storage.upload(file.name, file);
        cookies().set('session', body.token);
        return redirect(body.next);
      }
    `,
    'src/app/api/tasks/route.ts',
  );
  const checklist = checklistFor(snapshot);
  for (const id of [
    'TW-CTRL-INJECTION-001',
    'TW-CTRL-OUTBOUND-001',
    'TW-CTRL-REDIRECT-001',
    'TW-CTRL-UPLOAD-001',
    'TW-CTRL-SESSION-001',
  ])
    assert.equal(
      checklist.controls.find((control) => control.id === id)?.status,
      'GAP_CANDIDATE',
      id,
    );
  assert.equal(checklist.packVersion, '0.2.0');
});

test('webhook signature calls do not hide unsafe body parsing order', () => {
  const snapshot = snapshotOf(
    `
      export async function POST(request: Request) {
        const body = await request.json();
        verifySignature(body);
        return db.event.create({ data: body });
      }
    `,
    'src/app/api/webhooks/provider/route.ts',
  );
  const checklist = checklistFor(snapshot);
  assert.equal(
    checklist.controls.find((control) => control.id === 'TW-CTRL-WEBHOOK-001')?.status,
    'GAP_CANDIDATE',
  );
});
