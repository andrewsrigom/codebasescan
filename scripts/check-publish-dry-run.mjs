import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const metadataRewritePattern = /auto-corrected|errors corrected|invalid and removed/i;

const assertMetadataIsStable = (output) => {
  if (metadataRewritePattern.test(output)) {
    throw new Error(`npm would rewrite package metadata before publishing:\n${output.trim()}`);
  }
};

try {
  const { stderr } = await execute(npm, ['publish', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: root,
    maxBuffer: 16 * 1024 * 1024,
  });

  assertMetadataIsStable(stderr);
  console.log('npm publish dry-run passed without package metadata rewrites.');
} catch (error) {
  const output = `${String(error?.stdout ?? '')}\n${String(error?.stderr ?? '')}`;
  assertMetadataIsStable(output);

  if (!/cannot publish over the previously published versions/i.test(output)) throw error;

  const { stdout, stderr } = await execute(
    process.execPath,
    [path.join(root, 'scripts/publish-release.mjs')],
    {
      cwd: root,
      maxBuffer: 16 * 1024 * 1024,
    },
  );

  process.stdout.write(stdout);
  process.stderr.write(stderr);
  console.log('Published package integrity replaced the unavailable npm publish dry-run.');
}
