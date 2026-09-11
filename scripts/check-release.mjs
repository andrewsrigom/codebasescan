import { readFile } from 'node:fs/promises';

const expectedRepository = 'git+https://github.com/andrewsrigom/codebasescan.git';
const mode = process.argv[2] ?? 'prepare';
const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

requireValue(packageJson.name === 'codebasescan', 'Package name must remain codebasescan.');
requireValue(
  typeof packageJson.version === 'string' &&
    /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(packageJson.version),
  'Package version must be valid semver.',
);
requireValue(packageJson.license === 'MIT', 'Package license must remain MIT.');
requireValue(
  packageJson.repository?.url === expectedRepository,
  'Package repository must match the public provenance source.',
);
requireValue(packageJson.bin?.codebasescan === 'bin/codebasescan.mjs', 'CLI bin is missing.');
requireValue(packageJson.publishConfig?.access === 'public', 'npm access must be public.');
requireValue(packageJson.publishConfig?.provenance === true, 'npm provenance must be enabled.');
requireValue(
  typeof packageJson.private === 'boolean',
  'The private publication guard must be explicit.',
);

if (mode === 'publish') {
  const tag = process.env.RELEASE_TAG;
  requireValue(packageJson.private === false, 'Remove private: true only in the release commit.');
  requireValue(tag === `v${packageJson.version}`, `Release tag must be v${packageJson.version}.`);
} else {
  requireValue(mode === 'prepare', 'Use prepare or publish mode.');
}

console.log(
  `Release metadata valid for ${packageJson.name}@${packageJson.version} (${mode}, private=${packageJson.private}).`,
);
