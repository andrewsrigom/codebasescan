import ts from 'typescript';
import { digest } from '../domain/findings.ts';
import type {
  DatabaseContractAnalysis,
  DatabaseContractEntity,
  DatabaseContractLocation,
  DatabaseMigrationReference,
  DatabaseSourceReference,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';

const migrationPath = /(?:^|\/)(?:migrations?|drizzle)(?:\/|$)/i;
const sourcePattern = /\.[cm]?[jt]sx?$/i;
const drizzleBuilders = new Set(['pgTable', 'mysqlTable', 'sqliteTable', 'singlestoreTable']);
const databaseOperations = new Set([
  'findunique',
  'findfirst',
  'findmany',
  'create',
  'update',
  'upsert',
  'delete',
  'executeraw',
  'queryraw',
  'transaction',
]);
const genericEntityNames = new Set([
  'db',
  'database',
  'repository',
  'model',
  'client',
  'prisma',
  'drizzle',
  'query',
]);
const maximumSchemaFiles = 100;
const maximumMigrationFiles = 500;
const maximumEntities = 2_000;
const maximumReferencesPerEntity = 100;

interface RawSourceReference extends DatabaseSourceReference {
  entityToken: string;
}

interface TypeScriptDatabaseEvidence {
  declarations: DatabaseContractLocation[];
  bindings: { identifier: string; name: string }[];
  sourceReferences: RawSourceReference[];
}

function lineOf(content: string, index: number): number {
  return content.slice(0, Math.max(0, index)).split('\n').length;
}

function normalizedEntity(name: string): string {
  return name
    .split('.')
    .at(-1)!
    .replace(/^[`"'\[]+|[`"'\]]+$/g, '')
    .replace(/[^A-Za-z0-9]/g, '')
    .toLowerCase();
}

function scriptKind(file: string): ts.ScriptKind {
  if (/\.[cm]?tsx$/i.test(file)) return ts.ScriptKind.TSX;
  if (/\.jsx$/i.test(file)) return ts.ScriptKind.JSX;
  if (/\.[cm]?js$/i.test(file)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function typescriptDatabaseEvidence(file: SourceFile): TypeScriptDatabaseEvidence {
  const source = ts.createSourceFile(
    file.path,
    file.content,
    ts.ScriptTarget.Latest,
    true,
    scriptKind(file.path),
  );
  const declarations: DatabaseContractLocation[] = [];
  const bindings: TypeScriptDatabaseEvidence['bindings'] = [];
  const sourceReferences: RawSourceReference[] = [];
  const reference = (node: ts.CallExpression, token: string): void => {
    if (!token) return;
    sourceReferences.push({
      entityToken: token.slice(0, 300),
      file: file.path,
      line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1,
      signal: node.expression.getText(source).slice(0, 500),
    });
  };
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      drizzleBuilders.has(node.expression.text) &&
      node.arguments[0] &&
      ts.isStringLiteralLike(node.arguments[0])
    )
      declarations.push({
        file: file.path,
        line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1,
        kind: 'drizzle-table',
        name: node.arguments[0].text.slice(0, 300),
      });
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      drizzleBuilders.has(node.expression.text) &&
      node.arguments[0] &&
      ts.isStringLiteralLike(node.arguments[0]) &&
      ts.isVariableDeclaration(node.parent) &&
      ts.isIdentifier(node.parent.name)
    )
      bindings.push({
        identifier: node.parent.name.text,
        name: node.arguments[0].text.slice(0, 300),
      });
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const terminal = node.expression.name.text.toLowerCase();
      const expression = node.expression.getText(source);
      const firstArgument = node.arguments[0];
      if (
        ['from', 'insert', 'update', 'delete'].includes(terminal) &&
        /(?:^|\W)(?:db|database|tx|supabase|prisma)(?:\W|$)/i.test(expression) &&
        firstArgument &&
        (ts.isIdentifier(firstArgument) || ts.isStringLiteralLike(firstArgument))
      )
        reference(node, firstArgument.text);
      const queryEntity = /(?:^|\W)(?:db|database|tx)\.query\.([A-Za-z_$][A-Za-z0-9_$]*)\./i.exec(
        expression,
      )?.[1];
      if (queryEntity) reference(node, queryEntity);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { declarations, bindings, sourceReferences };
}

function prismaDeclarations(file: SourceFile): DatabaseContractLocation[] {
  const locations: DatabaseContractLocation[] = [];
  const pattern = /\bmodel\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([\s\S]*?)\}/g;
  for (const match of file.content.matchAll(pattern)) {
    const mapped = /@@map\s*\(\s*["']([^"']+)["']\s*\)/.exec(match[2] ?? '');
    locations.push({
      file: file.path,
      line: lineOf(file.content, match.index ?? 0),
      kind: 'prisma-model',
      name: (mapped?.[1] ?? match[1]!).slice(0, 300),
    });
  }
  return locations;
}

function sqlReferences(file: SourceFile): DatabaseMigrationReference[] {
  const references: DatabaseMigrationReference[] = [];
  const pattern =
    /\b(CREATE|ALTER|DROP)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?((?:"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z0-9_$-]+)(?:\s*\.\s*(?:"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z0-9_$-]+))?)/gi;
  for (const match of file.content.matchAll(pattern)) {
    const operation = match[1]!.toLowerCase() as DatabaseMigrationReference['operation'];
    references.push({
      file: file.path,
      line: lineOf(file.content, match.index ?? 0),
      operation,
      name: match[2]!.replace(/\s+/g, '').slice(0, 300),
    });
  }
  return references;
}

function sourceReferences(
  profile: ProjectProfile,
  rawReferences: RawSourceReference[],
  bindings: Map<string, Set<string>>,
): Map<string, DatabaseSourceReference[]> {
  const references = new Map<string, DatabaseSourceReference[]>();
  const seen = new Set<string>();
  const add = (key: string, reference: DatabaseSourceReference): void => {
    const identity = `${key}:${reference.file}:${reference.line}:${reference.signal}`;
    if (seen.has(identity)) return;
    seen.add(identity);
    const current = references.get(key) ?? [];
    if (current.length < maximumReferencesPerEntity) current.push(reference);
    references.set(key, current);
  };
  for (const raw of rawReferences) {
    const names = bindings.get(raw.entityToken);
    const name = names?.size === 1 ? [...names][0]! : raw.entityToken;
    const key = normalizedEntity(name);
    if (key)
      add(key, {
        file: raw.file,
        line: raw.line,
        signal: raw.signal,
      });
  }
  for (const fact of profile.facts.filter((candidate) => candidate.kind === 'database')) {
    const segments = fact.signal.split('.').filter(Boolean);
    const terminal = segments.at(-1)?.toLowerCase();
    if (!terminal || !databaseOperations.has(terminal)) continue;
    const rawName = [...segments]
      .slice(0, -1)
      .reverse()
      .find((segment) => !genericEntityNames.has(segment.toLowerCase()));
    if (!rawName) continue;
    const key = normalizedEntity(rawName);
    if (!key) continue;
    add(key, {
      file: fact.file,
      line: fact.line,
      signal: fact.signal.slice(0, 500),
    });
  }
  return references;
}

export function scanDatabaseContract(
  snapshot: Snapshot,
  profile: ProjectProfile,
): { analysis: DatabaseContractAnalysis; run: ScannerRun } {
  const started = performance.now();
  const schemaLocations: DatabaseContractLocation[] = [];
  const schemaFiles: DatabaseContractAnalysis['schemaFiles'] = [];
  const migrationReferences: DatabaseMigrationReference[] = [];
  const migrationFiles: DatabaseContractAnalysis['migrationFiles'] = [];
  const rawSourceReferences: RawSourceReference[] = [];
  const bindingNames = new Map<string, Set<string>>();
  let parseFailures = 0;

  for (const file of snapshot.files.filter((candidate) => candidate.scope === 'runtime')) {
    if (file.path.endsWith('.prisma')) {
      const declarations = prismaDeclarations(file);
      if (/\bmodel\s+/.test(file.content) && !declarations.length) parseFailures++;
      schemaLocations.push(...declarations);
      schemaFiles.push({ file: file.path, kind: 'prisma', entities: declarations.length });
      continue;
    }
    if (sourcePattern.test(file.path)) {
      const evidence = typescriptDatabaseEvidence(file);
      const declarations = evidence.declarations;
      rawSourceReferences.push(...evidence.sourceReferences);
      for (const binding of evidence.bindings) {
        const names = bindingNames.get(binding.identifier) ?? new Set<string>();
        names.add(binding.name);
        bindingNames.set(binding.identifier, names);
      }
      if (declarations.length) {
        schemaLocations.push(...declarations);
        schemaFiles.push({ file: file.path, kind: 'drizzle', entities: declarations.length });
      }
      continue;
    }
    if (!file.path.endsWith('.sql')) continue;
    const references = sqlReferences(file);
    if (migrationPath.test(file.path)) {
      migrationReferences.push(...references);
      migrationFiles.push({ file: file.path, references: references.length });
    } else {
      const declarations = references
        .filter((reference) => reference.operation === 'create')
        .map((reference): DatabaseContractLocation => ({
          file: reference.file,
          line: reference.line,
          kind: 'sql-table',
          name: reference.name,
        }));
      if (declarations.length) {
        schemaLocations.push(...declarations);
        schemaFiles.push({ file: file.path, kind: 'sql', entities: declarations.length });
      }
    }
  }

  const sourceByEntity = sourceReferences(profile, rawSourceReferences, bindingNames);
  const declarationsByEntity = new Map<string, DatabaseContractLocation[]>();
  for (const declaration of schemaLocations) {
    const key = normalizedEntity(declaration.name);
    if (key) declarationsByEntity.set(key, [...(declarationsByEntity.get(key) ?? []), declaration]);
  }
  const migrationsByEntity = new Map<string, DatabaseMigrationReference[]>();
  for (const reference of migrationReferences) {
    const key = normalizedEntity(reference.name);
    if (key) migrationsByEntity.set(key, [...(migrationsByEntity.get(key) ?? []), reference]);
  }

  const keys = [
    ...new Set([
      ...declarationsByEntity.keys(),
      ...migrationsByEntity.keys(),
      ...sourceByEntity.keys(),
    ]),
  ].sort();
  const hasSchemas = schemaFiles.length > 0;
  const hasMigrations = migrationFiles.length > 0;
  const entities: DatabaseContractEntity[] = keys.slice(0, maximumEntities).map((key) => {
    const declarations = declarationsByEntity.get(key) ?? [];
    const migrations = migrationsByEntity.get(key) ?? [];
    const sources = sourceByEntity.get(key) ?? [];
    const gaps: DatabaseContractEntity['gaps'] = [];
    if (hasSchemas && sources.length && !declarations.length)
      gaps.push('source-without-declaration');
    if (
      hasMigrations &&
      declarations.length &&
      !migrations.some((reference) => reference.operation === 'create')
    )
      gaps.push('declaration-without-create-migration');
    if (hasSchemas && migrations.length && !declarations.length)
      gaps.push('migration-without-declaration');
    const name = declarations[0]?.name ?? migrations[0]?.name ?? key;
    return {
      id: `database-entity-${digest(key).slice(0, 16)}`,
      name,
      normalizedName: key,
      declarations: declarations.slice(0, maximumReferencesPerEntity),
      migrations: migrations.slice(0, maximumReferencesPerEntity),
      sourceReferences: sources.slice(0, maximumReferencesPerEntity),
      gaps,
    };
  });
  const truncated =
    snapshot.truncated ||
    profile.truncated ||
    schemaFiles.length > maximumSchemaFiles ||
    migrationFiles.length > maximumMigrationFiles ||
    keys.length > maximumEntities;
  const status: DatabaseContractAnalysis['status'] =
    !hasSchemas && !hasMigrations
      ? 'unsupported'
      : truncated || parseFailures > 0 || profile.status !== 'complete'
        ? 'partial'
        : 'complete';
  const gapCandidates = entities.filter((entity) => entity.gaps.length).length;
  const analysis: DatabaseContractAnalysis = {
    schemaVersion: 1,
    version: '1.0.0',
    status,
    schemaFiles: schemaFiles.slice(0, maximumSchemaFiles),
    migrationFiles: migrationFiles.slice(0, maximumMigrationFiles),
    entities,
    summary: {
      schemaFiles: schemaFiles.length,
      migrationFiles: migrationFiles.length,
      declaredEntities: declarationsByEntity.size,
      migrationEntities: migrationsByEntity.size,
      sourceEntities: sourceByEntity.size,
      linkedEntities: entities.filter(
        (entity) =>
          entity.declarations.length > 0 &&
          (entity.migrations.length > 0 || entity.sourceReferences.length > 0),
      ).length,
      gapCandidates,
    },
    parseFailures,
    truncated,
    limitations: [
      'Schema, migration, and source files are parsed as inert text or syntax trees; no ORM, migration, or target code is executed.',
      'A gap is a consistency candidate, not proof that a database object is missing or stale at runtime.',
      'Squashed, externally managed, generated, renamed, or excluded migrations can make declaration-to-migration evidence incomplete.',
      'Source entity correlation is limited to statically mapped database call chains and can miss aliases, raw SQL, repositories, and dynamic access.',
      'Names are compared case-insensitively after punctuation removal; semantic renames cannot be inferred.',
    ],
  };
  return {
    analysis,
    run: {
      id: 'database-contract',
      name: 'Database schema and migration consistency',
      status: status === 'unsupported' ? 'skipped' : status === 'partial' ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: 0,
      detail:
        status === 'unsupported'
          ? 'No captured Prisma, Drizzle, SQL schema, or migration declaration was found.'
          : `Mapped ${declarationsByEntity.size} declared, ${migrationsByEntity.size} migration, and ${sourceByEntity.size} source-referenced database entities; ${gapCandidates} consistency candidate(s).`,
      version: '1.0.0',
    },
  };
}
