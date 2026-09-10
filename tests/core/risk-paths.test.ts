import test from 'node:test';
import assert from 'node:assert/strict';
import { makeFinding, sourceEvidence } from '../../src/domain/findings.ts';
import { buildRiskCorrelation } from '../../src/domain/risk-paths.ts';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('risk correlation retains only proven entrypoint-to-operation source paths', () => {
  const snapshot = snapshotFromFiles({
    'src/app/api/accounts/route.ts': `
      import { updateAccount } from '../../../lib/accounts';
      export async function PATCH(request: Request) {
        const body = await request.json();
        return updateAccount(body);
      }
    `,
    'src/lib/accounts.ts': `
      export async function updateAccount(input: { name: string }) {
        return database.account.update({ data: { name: input.name } });
      }
    `,
    'src/lib/unrelated.ts': `
      export function unrelated() {
        return database.audit.create({ data: { event: 'test' } });
      }
    `,
  });
  const route = snapshot.files.find((file) => file.path.endsWith('/route.ts'))!;
  const unrelated = snapshot.files.find((file) => file.path.endsWith('/unrelated.ts'))!;
  const routeFinding = makeFinding({
    source: 'ast',
    ruleId: 'TW-AST001',
    title: 'Missing authentication evidence',
    category: 'authentication',
    severity: 'high',
    sourceSeverity: 'HIGH',
    description: 'The route reaches a sensitive operation without mapped authentication.',
    remediation: 'Require an authenticated session.',
    cwe: ['CWE-306'],
    evidence: [sourceEvidence(route, 4, 'PATCH receives request data.')],
    confidence: 'high',
    exposure: 'potentially_public',
    priority: 90,
  });
  const unrelatedFinding = makeFinding({
    source: 'ast',
    ruleId: 'TW-AST999',
    title: 'Unrelated candidate',
    category: 'configuration',
    severity: 'medium',
    sourceSeverity: 'MEDIUM',
    description: 'This candidate is not reachable from the route.',
    remediation: 'Review it separately.',
    cwe: [],
    evidence: [sourceEvidence(unrelated, 3, 'Unrelated function.')],
    confidence: 'high',
    exposure: 'unknown',
    priority: 40,
  });
  const profile = profileProject(snapshot).profile;

  const result = buildRiskCorrelation(profile, [routeFinding, unrelatedFinding]);

  assert.equal(result.status, 'complete');
  assert.equal(result.paths.length, 1);
  assert.equal(result.summary.correlatedFindings, 1);
  assert.equal(result.summary.uncorrelatedFindings, 1);
  assert.deepEqual(result.paths[0]?.findingIds, [routeFinding.id]);
  assert.equal(result.paths[0]?.factKind, 'database');
  assert.deepEqual(
    result.paths[0]?.steps.map((step) => step.kind),
    ['entrypoint', 'call', 'sensitive-operation'],
  );
  assert.deepEqual(result, buildRiskCorrelation(profile, [routeFinding, unrelatedFinding]));
});
