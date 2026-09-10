import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanDatabaseContract } from '../../src/scanners/database-contract.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('database contract links Prisma models, SQL migrations, and mapped source operations', () => {
  const snapshot = snapshotFromFiles({
    'prisma/schema.prisma': `model User {
  id String @id
  @@map("users")
}`,
    'prisma/migrations/001_init/migration.sql': 'CREATE TABLE "users" ("id" text primary key);',
    'src/users.ts': 'export async function list() { return prisma.users.findMany(); }',
  });
  const result = scanDatabaseContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.status, 'complete');
  assert.equal(result.analysis.summary.declaredEntities, 1);
  assert.equal(result.analysis.summary.migrationEntities, 1);
  assert.equal(result.analysis.summary.sourceEntities, 1);
  assert.equal(result.analysis.summary.gapCandidates, 0);
  assert.equal(result.analysis.entities[0]?.normalizedName, 'users');
});

test('database contract retains bounded declaration and migration differences', () => {
  const snapshot = snapshotFromFiles({
    'src/db/schema.ts': `
import { pgTable } from "drizzle-orm/pg-core";
export const accounts = pgTable("accounts", {});
export const invoices = pgTable("invoices", {});
`,
    'drizzle/0001_accounts.sql':
      'CREATE TABLE accounts (id text); CREATE TABLE legacy_events (id text);',
    'src/db/read.ts': `
export async function read() {
  await db.update(accounts).set({ active: true });
  return db.query.auditLogs.findMany();
}`,
  });
  const result = scanDatabaseContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.summary.gapCandidates, 3);
  assert.deepEqual(
    result.analysis.entities
      .filter((entity) => entity.gaps.length)
      .map((entity) => [entity.normalizedName, entity.gaps]),
    [
      ['auditlogs', ['source-without-declaration']],
      ['invoices', ['declaration-without-create-migration']],
      ['legacyevents', ['migration-without-declaration']],
    ],
  );
  assert.equal(
    result.analysis.entities.find((entity) => entity.normalizedName === 'accounts')
      ?.sourceReferences.length,
    1,
  );
});

test('database source calls without a captured schema stay unsupported rather than gaps', () => {
  const snapshot = snapshotFromFiles({
    'src/users.ts': 'export async function list() { return prisma.user.findMany(); }',
  });
  const result = scanDatabaseContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.status, 'unsupported');
  assert.equal(result.analysis.summary.sourceEntities, 1);
  assert.equal(result.analysis.summary.gapCandidates, 0);
  assert.equal(result.run.status, 'skipped');
});

test('malformed Prisma declarations make database contract coverage partial', () => {
  const snapshot = snapshotFromFiles({
    'prisma/schema.prisma': 'model User { id String',
  });
  const result = scanDatabaseContract(snapshot, profileProject(snapshot).profile);
  assert.equal(result.analysis.status, 'partial');
  assert.equal(result.analysis.parseFailures, 1);
  assert.equal(result.analysis.summary.gapCandidates, 0);
});
