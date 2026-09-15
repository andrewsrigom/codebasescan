import path from 'node:path';
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, realpath, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const skillName = 'codebasescan-review';
const bundledFiles = [
  'SKILL.md',
  path.join('agents', 'openai.yaml'),
  path.join('references', 'contract.md'),
] as const;

async function existingMetadata(location: string) {
  try {
    return await lstat(location);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return undefined;
    throw error;
  }
}

async function rejectSymlink(location: string): Promise<void> {
  const metadata = await existingMetadata(location);
  if (metadata?.isSymbolicLink())
    throw new Error(`Refusing to install through symbolic link: ${location}`);
}

export async function installCodexSkill(project: string, force = false): Promise<string> {
  const projectRoot = await realpath(path.resolve(project));
  if (!(await stat(projectRoot)).isDirectory())
    throw new Error('Skill target must be a directory.');

  const agentDirectory = path.join(projectRoot, '.agents');
  const skillsDirectory = path.join(agentDirectory, 'skills');
  const destination = path.join(skillsDirectory, skillName);
  for (const location of [agentDirectory, skillsDirectory, destination])
    await rejectSymlink(location);

  const source = fileURLToPath(new URL(`../../skills/${skillName}/`, import.meta.url));
  for (const relative of bundledFiles) {
    const target = path.join(destination, relative);
    const metadata = await existingMetadata(target);
    if (metadata?.isSymbolicLink())
      throw new Error(`Refusing to overwrite symbolic link: ${target}`);
    if (metadata && !force)
      throw new Error(`Skill file already exists: ${target}. Pass --force to replace it.`);
  }

  for (const relative of bundledFiles) {
    const target = path.join(destination, relative);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await copyFile(path.join(source, relative), target, force ? 0 : constants.COPYFILE_EXCL);
    await chmod(target, 0o600);
  }
  return destination;
}
