import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const { stdout } = await execute(npm, ['pack', '--dry-run', '--json', '--ignore-scripts'], {
  cwd: root,
  maxBuffer: 16 * 1024 * 1024,
});
const [pack] = JSON.parse(stdout);
if (!pack || !Array.isArray(pack.files)) throw new Error('npm did not return a package inventory.');
const files = new Set(pack.files.map((file) => file.path));
const required = [
  'LICENSE',
  'README.md',
  'bin/codebasescan.mjs',
  'configs/gitleaks.toml',
  'configs/codebasescan.config.schema.json',
  'configs/semgrep.yml',
  'dist/cli/main.js',
  'dist/server/config.js',
  'package.json',
];
for (const file of required)
  if (!files.has(file)) throw new Error(`Packed CLI is missing ${file}.`);
for (const file of files)
  if (file.startsWith('src/') || file === '.env.local' || file.startsWith('.codebasescan/'))
    throw new Error(`Packed CLI contains private development data: ${file}.`);
console.log(
  `Package check passed: ${pack.entryCount} files, ${pack.size} packed bytes, ${pack.unpackedSize} unpacked bytes.`,
);
