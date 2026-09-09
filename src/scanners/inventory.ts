import type { Dependency, Snapshot } from '../domain/types.ts';
export function inventory(snapshot: Snapshot): Dependency[] {
  const dependencies: Dependency[] = [];
  for (const file of snapshot.files) {
    if (file.path.split('/').at(-1) !== 'package.json')
      continue;
    try {
      const manifest = JSON.parse(file.content) as Record<string, unknown>;
      for (const [key, scope] of [['dependencies', 'runtime'], ['devDependencies', 'development']] as const) {
        const section = manifest[key];
        if (!section || typeof section !== 'object' || Array.isArray(section))
          continue;
        for (const [name, version] of Object.entries(section)) {
          if (typeof version === 'string')
            dependencies.push({ name, requestedVersion: version, manifest: file.path, scope });
        }
      }
    }
    catch { /* An invalid manifest is not an empty vulnerability scan. */ }
  }
  return dependencies.sort((a, b) => a.name.localeCompare(b.name));
}
