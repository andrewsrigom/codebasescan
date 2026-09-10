import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { AuditStore } from '../../src/server/store.ts';

test(
  'a replacement worker recovers state after an actual SIGKILL',
  { skip: process.platform === 'win32', timeout: 10_000 },
  async (context) => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-sigkill-'));
    context.after(() => rm(directory, { recursive: true, force: true }));
    const databasePath = path.join(directory, 'application.sqlite');
    const child = spawn(
      process.execPath,
      [
        '--experimental-strip-types',
        path.resolve('tests/fixtures/hold-worker-lock.ts'),
        databasePath,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    context.after(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    });
    const chunk = await new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Crash fixture did not start.')), 3_000);
      child.stdout!.once('data', (value: Buffer) => {
        clearTimeout(timer);
        resolve(value);
      });
      child.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
    const auditId = chunk.toString('utf8').trim();
    assert.match(auditId, /^[0-9a-f-]{36}$/);

    assert.equal(child.kill('SIGKILL'), true);
    await once(child, 'exit');

    const store = new AuditStore(databasePath);
    context.after(() => store.close());
    assert.equal(store.audit(auditId).status, 'running');
    const token = store.acquireWorker();
    assert.equal(store.audit(auditId).status, 'queued');
    assert.match(store.audit(auditId).error ?? '', /Previous worker stopped/);
    store.releaseWorker(token);
  },
);
