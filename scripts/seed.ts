import path from 'node:path';
import { configuration } from '../src/server/config.ts';
import { AuditStore } from '../src/server/store.ts';
import { disableTelemetry } from '../src/security/privacy.ts';
import { estimateProjectScope, validateProjectRoot } from '../src/security/paths.ts';
disableTelemetry();
process.umask(0o077);
const config = {
  ...configuration(),
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
  if (!audit || ['failed', 'cancelled'].includes(audit.status)) {
    const estimate = await estimateProjectScope(root);
    audit = store.enqueue(project.id, {
      scopePreflight: { ...estimate, truncationApproved: false },
    });
  }
  if (audit.status === 'queued') {
    store.claim(audit.id);
    await executeAudit(store, audit.id, config);
  }
  console.log(`Demo audit: ${audit.id}`);
  console.log(`Status: ${store.audit(audit.id).status}`);
  console.log('Run npm run dev, then open http://127.0.0.1:3000.');
} finally {
  store.releaseWorker(token);
  store.close();
}
