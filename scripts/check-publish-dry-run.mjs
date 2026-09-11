import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const { stderr } = await execute(npm, ['publish', '--dry-run', '--json', '--ignore-scripts'], {
  cwd: root,
  maxBuffer: 16 * 1024 * 1024,
});

if (/auto-corrected|errors corrected|invalid and removed/i.test(stderr)) {
  throw new Error(`npm would rewrite package metadata before publishing:\n${stderr.trim()}`);
}

console.log('npm publish dry-run passed without package metadata rewrites.');
