import { execFile } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const npmExecPath = process.env.npm_execpath;
if (process.platform === 'win32' && !npmExecPath)
  throw new Error('Run the release dry-run through npm so npm_execpath is available on Windows.');
const npm = process.platform === 'win32' ? process.execPath : 'npm';
const npmArguments = [
  ...(process.platform === 'win32' ? [npmExecPath] : []),
  'publish',
  '--dry-run',
  '--json',
  '--ignore-scripts',
];
const metadataRewritePattern = /auto-corrected|errors corrected|invalid and removed/i;

const assertMetadataIsStable = (output) => {
  if (metadataRewritePattern.test(output)) {
    throw new Error(`npm would rewrite package metadata before publishing:\n${output.trim()}`);
  }
};

const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-npm-dry-run-'));
const options = {
  cwd: root,
  maxBuffer: 16 * 1024 * 1024,
  env: { ...process.env, npm_config_cache: path.join(temporary, 'cache') },
};
try {
  try {
    const { stderr } = await execute(npm, npmArguments, options);
    assertMetadataIsStable(stderr);
    console.log('npm publish dry-run passed without package metadata rewrites.');
  } catch (error) {
    const output = `${String(error?.stdout ?? '')}\n${String(error?.stderr ?? '')}`;
    assertMetadataIsStable(output);
    if (!/cannot publish over the previously published versions/i.test(output)) throw error;
    const { stdout, stderr } = await execute(
      process.execPath,
      [path.join(root, 'scripts/publish-release.mjs')],
      options,
    );
    process.stdout.write(stdout);
    process.stderr.write(stderr);
    console.log('Published package integrity replaced the unavailable npm publish dry-run.');
  }
} finally {
  await rm(temporary, { recursive: true, force: true });
}
