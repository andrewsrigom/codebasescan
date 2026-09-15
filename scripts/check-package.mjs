import { execFile } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const npmArguments = ['pack', '--dry-run', '--json', '--ignore-scripts'];
const npmExecPath = process.env.npm_execpath;
const npmCommand = process.platform === 'win32' && npmExecPath ? process.execPath : 'npm';
const npmCommandArguments =
  process.platform === 'win32' && npmExecPath ? [npmExecPath, ...npmArguments] : npmArguments;
const maximumPackedBytes = 2 * 1024 * 1024;
const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-package-check-'));
let stdout;
try {
  ({ stdout } = await execute(npmCommand, npmCommandArguments, {
    cwd: root,
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, npm_config_cache: path.join(temporary, 'cache') },
  }));
} finally {
  await rm(temporary, { recursive: true, force: true });
}
const [pack] = JSON.parse(stdout);
if (!pack || !Array.isArray(pack.files)) throw new Error('npm did not return a package inventory.');
if (pack.size > maximumPackedBytes)
  throw new Error(`Packed CLI is ${pack.size} bytes; the v1 limit is ${maximumPackedBytes} bytes.`);
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
  'skills/codebasescan-review/SKILL.md',
  'skills/codebasescan-review/agents/openai.yaml',
  'skills/codebasescan-review/references/contract.md',
  'skills/codebasescan-gap-review/SKILL.md',
  'skills/codebasescan-verify-fix/SKILL.md',
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
