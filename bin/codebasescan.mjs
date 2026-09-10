#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));
const environment = path.resolve('.env.local');
const child = spawn(
  process.execPath,
  [
    ...(existsSync(environment) ? [`--env-file=${environment}`] : []),
    cli,
    ...process.argv.slice(2),
  ],
  { stdio: 'inherit', env: process.env },
);

for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));

child.on('error', () => {
  console.error('CodebaseScan could not start. Use Node.js 22.16 or newer.');
  process.exitCode = 1;
});
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exitCode = code ?? 1;
});
