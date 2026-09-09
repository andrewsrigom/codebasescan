import { Command } from '@langchain/langgraph';
import { SqliteSaver } from '@langchain/langgraph-checkpoint-sqlite';
import { buildAuditGraph } from './audit-graph.ts';
import { createLocalReviewer } from './model.ts';
import type { Configuration } from '../server/config.ts';
import type { AuditStore } from '../server/store.ts';
export async function executeAudit(store: AuditStore, auditId: string, config: Configuration, signal?: AbortSignal): Promise<void> {
  const audit = store.audit(auditId);
  const project = store.project(audit.projectId);
  const checkpointer = SqliteSaver.fromConnString(config.checkpointPath);
  try {
    const graph = buildAuditGraph({ root: project.root, projectName: project.name, config, store, checkpointer, reviewer: config.aiMode === 'ollama' ? createLocalReviewer(config.model) : null, signal });
    const invocation = { configurable: { thread_id: audit.id }, recursionLimit: 100, signal };
    const previous = await graph.getState(invocation);
    const input = audit.resumeNote
      ? new Command({ resume: { note: audit.resumeNote } })
      : previous.values && Object.keys(previous.values).length ? null : { auditId: audit.id };
    await graph.invoke(input, invocation);
    if (store.audit(audit.id).status === 'cancelled')
      return;
    const current = await graph.getState(invocation);
    store.transition(audit.id, current.next.length ? 'awaiting_review' : 'completed');
  }
  finally {
    // The official saver owns its SQLite connection.
    checkpointer.db.close();
  }
}
