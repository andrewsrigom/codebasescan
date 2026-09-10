import path from 'node:path';
import { rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const output = path.join(root, 'dist');

if (path.dirname(output) !== root || path.basename(output) !== 'dist')
  throw new Error('Refusing to clean an unexpected CLI output directory.');

await rm(output, { recursive: true, force: true });
