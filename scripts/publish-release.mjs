import { execFile, spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const spec = `${packageJson.name}@${packageJson.version}`;

const { stdout: packOutput, stderr: packWarnings } = await execute(
  npm,
  ['pack', '--dry-run', '--json', '--ignore-scripts'],
  { cwd: root, maxBuffer: 16 * 1024 * 1024 },
);
if (/auto-corrected|errors corrected|invalid and removed/i.test(packWarnings)) {
  throw new Error(`npm would rewrite package metadata before publishing:\n${packWarnings.trim()}`);
}
const [pack] = JSON.parse(packOutput);
if (!pack?.integrity) throw new Error('npm did not return the local package integrity.');

let publishedIntegrity;
try {
  const { stdout } = await execute(npm, ['view', spec, 'dist.integrity', '--json'], {
    cwd: root,
    maxBuffer: 1024 * 1024,
  });
  publishedIntegrity = JSON.parse(stdout);
} catch (error) {
  const stderr = String(error?.stderr ?? '');
  if (!stderr.includes('E404')) throw error;
}

if (publishedIntegrity) {
  if (publishedIntegrity !== pack.integrity) {
    throw new Error(`${spec} already exists with different package contents.`);
  }
  console.log(`${spec} already exists with matching integrity; publish is already complete.`);
  process.exit(0);
}

if (process.env.GITHUB_ACTIONS !== 'true') {
  throw new Error(
    'A missing release may be published only by the trusted GitHub Actions workflow.',
  );
}

const exitCode = await new Promise((resolve, reject) => {
  const child = spawn(npm, ['publish'], { cwd: root, stdio: 'inherit', env: process.env });
  child.once('error', reject);
  child.once('exit', (code) => resolve(code ?? 1));
});
if (exitCode !== 0) throw new Error(`npm publish exited with code ${exitCode}.`);
