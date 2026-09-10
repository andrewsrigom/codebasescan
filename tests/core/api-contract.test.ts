import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanApiContract } from '../../src/scanners/api-contract.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('API contract matches Next route parameters without executing the specification', () => {
  const snapshot = snapshotFromFiles({
    'openapi.yaml': `openapi: 3.1.0
paths:
  /api/users/{userId}:
    get:
      operationId: getUser
    post:
      operationId: updateUser
`,
    'src/app/api/users/[userId]/route.ts': `
export async function GET() { return Response.json({ ok: true }); }
export async function POST() { return Response.json({ ok: true }); }
`,
  });
  const profile = profileProject(snapshot).profile;
  const result = scanApiContract(snapshot, profile);
  assert.equal(result.analysis.status, 'complete');
  assert.equal(result.analysis.summary.declaredOperations, 2);
  assert.equal(result.analysis.summary.matchedOperations, 2);
  assert.equal(result.analysis.summary.declaredOnly, 0);
  assert.equal(result.analysis.summary.sourceOnly, 0);
  assert.equal(result.run.findings, 0);
});

test('API contract keeps declared-only and source-only differences as candidates', () => {
  const snapshot = snapshotFromFiles({
    'docs/swagger.json': JSON.stringify({
      swagger: '2.0',
      paths: {
        '/api/declared': { get: { operationId: 'declared' } },
      },
    }),
    'src/app/api/source/route.ts':
      'export async function POST() { return Response.json({ ok: true }); }',
  });
  const result = scanApiContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.summary.declaredOnly, 1);
  assert.equal(result.analysis.summary.sourceOnly, 1);
  assert.equal(result.analysis.summary.outsideContractScope, 0);
  assert.equal(result.analysis.declaredOperations[0]?.status, 'declared-only');
  assert.equal(result.analysis.sourceOperations[0]?.status, 'source-only');
  assert.match(result.analysis.limitations.join(' '), /not proof/i);
});

test('source routes outside a partial specification namespace are not mismatch candidates', () => {
  const snapshot = snapshotFromFiles({
    'openapi.json': JSON.stringify({
      openapi: '3.1.0',
      paths: {
        '/api/v1/analytics/overview': { get: {} },
        '/api/v1/analytics/usage': { get: {} },
      },
    }),
    'src/app/api/v1/analytics/overview/route.ts':
      'export async function GET() { return Response.json({ ok: true }); }',
    'src/app/api/admin/route.ts':
      'export async function POST() { return Response.json({ ok: true }); }',
  });
  const result = scanApiContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.specifications[0]?.pathScope, '/api/v1/analytics');
  assert.equal(result.analysis.summary.sourceOnly, 0);
  assert.equal(result.analysis.summary.outsideContractScope, 1);
  assert.equal(
    result.analysis.sourceOperations.find((operation) => operation.path === '/api/admin')?.status,
    'outside-contract-scope',
  );
});

test('malformed and referenced path items make API contract coverage partial', () => {
  const snapshot = snapshotFromFiles({
    'openapi.yaml': `openapi: 3.1.0
paths:
  /api/users:
    $ref: ./paths/users.yaml
`,
    'swagger.json': '{ invalid json',
  });
  const result = scanApiContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.status, 'partial');
  assert.equal(result.analysis.parseFailures, 1);
  assert.equal(result.analysis.unresolvedPathReferences, 1);
  assert.equal(result.analysis.summary.declaredOperations, 0);
});

test('projects without a captured specification remain unsupported instead of clean', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/source/route.ts':
      'export async function GET() { return Response.json({ ok: true }); }',
  });
  const result = scanApiContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.status, 'unsupported');
  assert.equal(result.analysis.summary.sourceOnly, 0);
  assert.equal(result.analysis.summary.outsideContractScope, 1);
  assert.equal(result.run.status, 'skipped');
});
