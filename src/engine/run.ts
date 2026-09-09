import { Command } from '@langchain/langgraph';
import { SqliteSaver } from '@langchain/langgraph-checkpoint-sqlite';
import { AuditState, buildAuditGraph } from './audit-graph.ts';
import { createLocalReviewer } from './model.ts';
import { createOpenAiReviewer } from './openai.ts';
import type { Configuration } from '../server/config.ts';
import type { AuditStore } from '../server/store.ts';
export async function executeAudit(
  store: AuditStore,
  auditId: string,
  config: Configuration,
  signal?: AbortSignal,
  options: { humanReview?: boolean } = {},
): Promise<void> {
  const audit = store.audit(auditId);
  const project = store.project(audit.projectId);
  const checkpointer = SqliteSaver.fromConnString(config.checkpointPath);
  try {
    const graph = buildAuditGraph({
      root: project.root,
      projectName: project.name,
      config,
      store,
      checkpointer,
      reviewer:
        config.aiMode === 'ollama'
          ? createLocalReviewer(config.model)
          : config.aiMode === 'openai'
            ? createOpenAiReviewer(config, store, audit.id)
            : null,
      httpProbe: audit.options.httpProbe,
      humanReview: options.humanReview,
      signal,
    });
    const invocation = {
      configurable: { thread_id: audit.id },
      recursionLimit: 100,
      durability: 'sync' as const,
      signal,
    };
    let previous = await graph.getState(invocation);
    if (audit.resumeNote) {
      for await (const snapshot of graph.getStateHistory(invocation, { limit: 100 })) {
        const publicationInterrupt = snapshot.tasks.some((task) =>
          task.interrupts.some(
            (item) =>
              typeof item.value === 'object' &&
              item.value !== null &&
              'kind' in item.value &&
              item.value.kind === 'publication_review',
          ),
        );
        if (publicationInterrupt) {
          previous = snapshot;
          break;
        }
      }
    }
    const interruptId = previous.tasks
      .flatMap((task) => task.interrupts)
      .find((item) => typeof item.id === 'string')?.id;
    const checkpointId = previous.config.configurable?.checkpoint_id;
    const reviewDecision = audit.resumeNote ? { note: audit.resumeNote } : null;
    if (audit.resumeNote && (!interruptId || typeof checkpointId !== 'string'))
      throw new Error('The saved publication review checkpoint could not be recovered.');
    const input = audit.resumeNote
      ? new Command<
          { note: string } | Record<string, { note: string }>,
          typeof AuditState.Update,
          never
        >({
          resume: interruptId ? { [interruptId]: reviewDecision! } : reviewDecision!,
        })
      : previous.values && Object.keys(previous.values).length
        ? null
        : { auditId: audit.id };
    const resumeInvocation = audit.resumeNote
      ? {
          ...invocation,
          configurable: { ...invocation.configurable, checkpoint_id: checkpointId as string },
        }
      : invocation;
    const result = await graph.invoke(input, resumeInvocation);
    if (store.audit(audit.id).status === 'cancelled') return;
    store.transition(audit.id, graph.isInterrupted(result) ? 'awaiting_review' : 'completed');
  } finally {
    // The official saver owns its SQLite connection.
    checkpointer.db.close();
  }
}
