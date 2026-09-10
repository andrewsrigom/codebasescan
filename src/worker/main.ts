import { setTimeout as delay } from 'node:timers/promises';
import { configuration } from '../server/config.ts';
import { AuditStore } from '../server/store.ts';
import { cleanupStaleScannerStaging } from '../scanners/external.ts';
import { disableRemoteTracing } from '../security/privacy.ts';
disableRemoteTracing();
process.umask(0o077);
const config = configuration();
const store = new AuditStore(config.databasePath);
const token = store.acquireWorker();
let stopping = false;
let active: AbortController | null = null;
let activeId: string | null = null;
for (const signal of ['SIGINT', 'SIGTERM'] as const)
  process.on(signal, () => {
    stopping = true;
    active?.abort();
  });
const heartbeat = setInterval(() => {
  store.heartbeat(token);
  if (activeId && store.audit(activeId).status === 'cancelled') active?.abort();
}, 2000);
console.log(
  `CodebaseScan worker ready. Read-only scans, AI ${config.aiMode}, one audit at a time.`,
);
try {
  const removedStagingDirectories = await cleanupStaleScannerStaging(config.temporaryDirectory);
  if (removedStagingDirectories)
    console.log(`Removed ${removedStagingDirectories} stale scanner staging directories.`);
  const { executeAudit } = await import('../engine/run.ts');
  while (!stopping) {
    const audit = store.claim();
    if (!audit) {
      await delay(700);
      continue;
    }
    active = new AbortController();
    activeId = audit.id;
    try {
      await executeAudit(store, audit.id, config, active.signal);
      console.log(`Audit ${audit.id}: ${store.audit(audit.id).status}`);
    } catch {
      if (stopping)
        store.transition(
          audit.id,
          'queued',
          'Worker stopped. A checkpoint resume will be attempted.',
        );
      else
        store.transition(
          audit.id,
          'failed',
          'Audit could not complete. No clean result is implied. Check local setup and source changes, then start a new audit.',
        );
      console.error(`Audit ${audit.id} did not complete.`);
    } finally {
      active = null;
      activeId = null;
    }
  }
} finally {
  clearInterval(heartbeat);
  store.releaseWorker(token);
  store.close();
}
