import { buildAuditPipeline } from './audit-pipeline.ts';
import type { Configuration } from '../server/config.ts';
import { auditWorkflowVersion } from '../domain/versions.ts';
import type { AuditExecutionStore } from './audit-store.ts';

export async function executeAudit(
  store: AuditExecutionStore,
  auditId: string,
  config: Configuration,
  signal?: AbortSignal,
): Promise<void> {
  const audit = store.audit(auditId);
  if (audit.workflowVersion !== auditWorkflowVersion)
    throw new Error(
      `Audit workflow ${audit.workflowVersion} is incompatible with ${auditWorkflowVersion}. Start a new audit.`,
    );
  const project = store.project(audit.projectId);
  const pipeline = buildAuditPipeline({
    root: project.root,
    projectName: project.name,
    config,
    store,
    httpProbe: audit.options.httpProbe,
    httpProbes: audit.options.httpProbes,
    gitHistorySecrets: audit.options.gitHistorySecrets,
    modes: audit.options.modes,
    signal,
  });
  await pipeline.invoke({ auditId: audit.id });
  if (store.audit(audit.id).status !== 'cancelled') store.transition(audit.id, 'completed');
}
