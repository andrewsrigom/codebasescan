import path from 'node:path';
import { configuration } from '../src/server/config.ts';
import { AuditStore } from '../src/server/store.ts';
import { disableRemoteTracing } from '../src/security/privacy.ts';
import { validateProjectRoot } from '../src/security/paths.ts';
disableRemoteTracing();
process.umask(0o077);
const config = {
  ...configuration(),
  aiMode: 'disabled' as const,
  semgrep: false,
  gitleaks: false,
  osv: false,
};
const store = new AuditStore(config.databasePath);
const token = store.acquireWorker();
try {
  const { executeAudit } = await import('../src/engine/run.ts');
  const root = await validateProjectRoot(
    path.resolve('fixtures/review-worthy-saas'),
    config.dataDirectory,
  );
  const project = store.registerProject('Review-worthy SaaS', root);
  let audit = store.audits().find((candidate) => candidate.projectId === project.id);
  if (!audit || ['failed', 'cancelled'].includes(audit.status)) audit = store.enqueue(project.id);
  if (audit.status === 'queued') {
    store.claim(audit.id);
    await executeAudit(store, audit.id, config);
  }
  if (process.argv.includes('--review') && store.audit(audit.id).status === 'awaiting_review') {
    store.publish(
      audit.id,
      'Demo fixture reviewed for demonstration. All unverified findings remain unresolved.',
    );
    store.claim(audit.id);
    await executeAudit(store, audit.id, config);
  }
  console.log(`Demo audit: ${audit.id}`);
  console.log(`Status: ${store.audit(audit.id).status}`);
  console.log(
    'Run npm run dev, then open http://127.0.0.1:3000. Start npm run worker before submitting publication review.',
  );
} finally {
  store.releaseWorker(token);
  store.close();
}
