import path from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import type { Snapshot, SourceFile } from '../domain/types.ts';
import { safeRelative } from '../security/paths.ts';

export async function writeSnapshotStage(
  snapshot: Snapshot,
  destination: string,
  include: (file: SourceFile) => boolean = () => true,
): Promise<void> {
  await mkdir(destination, { recursive: true, mode: 0o700 });
  for (const file of snapshot.files.filter(include)) {
    const target = path.join(destination, safeRelative(file.path));
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, file.content, { mode: 0o600, flag: 'wx' });
  }
}
