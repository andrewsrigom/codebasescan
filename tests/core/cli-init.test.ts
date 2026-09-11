import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { initializeProjectConfig } from '../../src/cli/init.ts';
import { renderCliHelp } from '../../src/cli/help.ts';

test('init creates a schema-backed config from inert package metadata', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-init-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  await writeFile(
    path.join(temporary, 'package.json'),
    JSON.stringify({
      packageManager: 'pnpm@10.0.0',
      scripts: { test: 'node --test', build: 'next build' },
    }),
  );
  const destination = await initializeProjectConfig(temporary);
  const config = JSON.parse(await readFile(destination, 'utf8')) as {
    $schema: string;
    verification: { packageManager: string; testScripts: string[]; buildScripts: string[] };
  };
  assert.equal(
    config.$schema,
    './node_modules/codebasescan/configs/codebasescan.config.schema.json',
  );
  assert.deepEqual(config.verification, {
    packageManager: 'pnpm',
    testScripts: ['test'],
    buildScripts: ['build'],
  });
  await assert.rejects(() => initializeProjectConfig(temporary), /already exists/);
});

test('CLI help separates the common workflow from command details', () => {
  assert.match(renderCliHelp(), /codebasescan init/);
  assert.match(renderCliHelp(), /codebasescan --version/);
  assert.match(renderCliHelp(), /No target project code is executed/);
  assert.match(renderCliHelp('audit'), /--non-interactive/);
  assert.doesNotMatch(renderCliHelp('doctor'), /--fail-on/);
});
