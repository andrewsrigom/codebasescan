import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { loadEnvFile } from 'node:process';
import { createRequire } from 'node:module';

if (existsSync('.env.local')) loadEnvFile('.env.local');

const require = createRequire(import.meta.url);
const mode = process.argv[2] ?? 'dev';
const port = process.env.TRACEWARD_PORT ?? '3000';
const args = mode === 'build' ? [mode] : [mode, '--hostname', '127.0.0.1', '--port', port];
const child = spawn(process.execPath, [require.resolve('next/dist/bin/next'), ...args], {
  stdio: 'inherit',
  env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' },
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('exit', (code) => process.exit(code ?? 1));
child.on('error', () => {
  console.error('Next.js could not start. Run npm install first.');
  process.exit(1);
});
