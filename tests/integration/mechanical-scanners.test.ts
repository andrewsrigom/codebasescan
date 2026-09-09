import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanArchitecture, scanDuplication } from '../../src/scanners/mechanical.ts';
import { snapshotFromFiles } from '../helpers.ts';

const repeatedBlock = `
export function normalizeUser(input: Record<string, unknown>) {
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  const email = typeof input.email === 'string' ? input.email.trim() : '';
  const role = typeof input.role === 'string' ? input.role.trim() : '';
  const team = typeof input.team === 'string' ? input.team.trim() : '';
  const enabled = input.enabled === true;
  const tags = Array.isArray(input.tags) ? input.tags.filter(Boolean) : [];
  const metadata = typeof input.metadata === 'object' ? input.metadata : {};
  return { name, email, role, team, enabled, tags, metadata };
}
`;

test('bundled mechanical scanners run against an inert staged snapshot', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-mechanical-test-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const snapshot = snapshotFromFiles({
    'src/a.ts': `import { b } from './b';\n${repeatedBlock}\nexport const a = b;\nthrow new Error('target code must not execute');`,
    'src/b.ts': `import { a } from './a';\n${repeatedBlock.replace('normalizeUser', 'normalizeAccount')}\nexport const b = a;`,
  });
  const profile = profileProject(snapshot).profile;
  const [architecture, duplication] = await Promise.all([
    scanArchitecture(snapshot, profile, temporary),
    scanDuplication(snapshot, temporary),
  ]);

  assert.ok(
    ['completed', 'partial'].includes(architecture.run.status),
    JSON.stringify(architecture),
  );
  assert.equal(architecture.run.version, '18.2.0');
  assert.equal(architecture.analysis?.modules, 2);
  assert.ok((architecture.analysis?.cycles.length ?? 0) >= 1);

  assert.ok(['completed', 'partial'].includes(duplication.run.status), JSON.stringify(duplication));
  assert.equal(duplication.run.version, '5.2.0');
  assert.ok((duplication.analysis?.clones ?? 0) >= 1);
  assert.ok((duplication.analysis?.blocks.length ?? 0) >= 1);
  assert.ok(!JSON.stringify(duplication.analysis).includes('target code must not execute'));
});
