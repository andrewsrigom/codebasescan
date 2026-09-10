# Database contract consistency

CodebaseScan correlates captured database declarations, SQL migration references, and statically
mapped database call chains. It reads them as inert data and never loads an ORM, connects to a
database, runs a migration, or executes target code.

## Inputs

Declarations include Prisma model blocks with optional table mapping, Drizzle pgTable, mysqlTable,
sqliteTable, and singlestoreTable calls with literal names, and CREATE TABLE statements in SQL
files outside migration directories. Files ending in .prisma are included in the bounded text
snapshot.

SQL files below migration, migrations, or drizzle directories supply CREATE, ALTER, and DROP TABLE
references. Source references come from database facts already mapped by the project profiler.

## Comparison

Names are compared case-insensitively after schema qualifiers, quotes, and punctuation are
removed. Each entity retains all bounded declaration, migration, and source locations.

Candidates are emitted only when the required comparison side exists:

- source-without-declaration requires at least one captured schema file;
- declaration-without-create-migration requires at least one captured migration file;
- migration-without-declaration requires at least one captured schema file.

When no schema and no migrations are captured, the analysis is unsupported and source references
do not become gaps. A candidate is incomplete captured evidence, not proof of runtime drift.

## Bounds and coverage

The output retains at most 100 schema files, 500 migration files, 2,000 entities, and 100
references of each kind per entity. Snapshot/profile truncation or malformed Prisma model syntax
makes coverage partial. Squashed, generated, external, renamed, or excluded migrations and dynamic
repository code can prevent a mechanical link. Full machine output is database-contract.json.
