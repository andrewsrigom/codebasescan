import test from 'node:test';
import assert from 'node:assert/strict';
import { enrichFindingQuality } from '../../src/domain/finding-quality.ts';
import { scanPatterns } from '../../src/scanners/builtin.ts';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanNextSecurity } from '../../src/scanners/next-security.ts';
import { snapshotOf } from '../helpers.ts';

test('finding quality prioritizes a potentially public high-severity route candidate', () => {
  const snapshot = snapshotOf(
    `
      export async function GET(_request: Request, { params }) {
        return Response.json(await db.account.findUnique({ where: { id: params.id } }));
      }
    `,
    'src/app/api/accounts/[id]/route.ts',
  );
  const profile = profileProject(snapshot).profile;
  const findings = enrichFindingQuality(scanNextSecurity(snapshot, profile).findings, profile);
  const scope = findings.find((finding) => finding.ruleId === 'TW-NEXT002');
  assert.equal(scope?.confidence, 'medium');
  assert.equal(scope?.exposure, 'potentially_public');
  assert.ok((scope?.priority ?? 0) >= 80);
});

test('finding quality keeps heuristic confidence and local runtime exposure explicit', () => {
  const finding = scanPatterns(snapshotOf('export const result = eval(input);'))[0]!;
  const [enriched] = enrichFindingQuality([finding], undefined, {
    requestedUrl: 'http://127.0.0.1:3000/',
    finalUrl: 'http://127.0.0.1:3000/',
    method: 'HEAD',
    statusCode: 200,
    redirects: 0,
    observedAt: '2026-09-09T00:00:00.000Z',
    durationMs: 1,
    headers: {},
    cookies: [],
  });
  assert.equal(enriched?.confidence, 'low');
  assert.equal(enriched?.exposure, 'unknown');
  assert.ok((enriched?.priority ?? 100) < 70);
});
