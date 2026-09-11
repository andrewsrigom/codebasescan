import { Annotation, END, START, StateGraph } from '@langchain/langgraph';
import type { Analysis, Finding, ProjectProfile, Snapshot } from '../domain/types.ts';
import type { Reviewer } from './model.ts';
import { createContextBroker } from './context-broker.ts';
import { agentReviewDepthLimits, type AgentReviewDepth } from '../domain/agent-depth.ts';
import { reviewRulesForFinding } from '../domain/agent-rules.ts';
const ReviewState = Annotation.Root({
  finding: Annotation<Finding>(),
  inspectedFiles: Annotation<string[]>({ reducer: (_, value) => value, default: () => [] }),
  contextIds: Annotation<string[]>({ reducer: (_, value) => value, default: () => [] }),
  requestedContextIds: Annotation<string[]>({ reducer: (_, value) => value, default: () => [] }),
  searchQueries: Annotation<string[]>({ reducer: (_, value) => value, default: () => [] }),
  context: Annotation<string>({ reducer: (_, value) => value, default: () => '' }),
  contextTruncated: Annotation<boolean>({ reducer: (_, value) => value, default: () => false }),
  rounds: Annotation<number>({ reducer: (_, value) => value, default: () => 0 }),
  analysis: Annotation<Analysis | null>({ reducer: (_, value) => value, default: () => null }),
});
export function buildReviewGraph(
  snapshot: Snapshot,
  reviewer: Reviewer,
  profile?: ProjectProfile,
  signal?: AbortSignal,
  depth: AgentReviewDepth = 'standard',
) {
  const limits = agentReviewDepthLimits[depth];
  return new StateGraph(ReviewState)
    .addNode('collect_context', async (state) => {
      const broker = createContextBroker(snapshot, state.finding, profile, depth);
      const searchIds =
        state.rounds === 0 ? [] : broker.search(state.searchQueries, state.contextIds);
      const requested =
        state.rounds === 0 ? broker.initialIds : [...state.requestedContextIds, ...searchIds];
      const delivery = broker.collect(
        requested,
        state.contextIds,
        state.context.length,
        state.rounds === 0,
      );
      return {
        context: [state.context, delivery.context].filter(Boolean).join('\n'),
        contextIds: [...state.contextIds, ...delivery.deliveredIds],
        inspectedFiles: [...new Set([...state.inspectedFiles, ...delivery.files])],
        contextTruncated: state.contextTruncated || delivery.truncated,
        rounds: state.rounds + 1,
      };
    })
    .addNode('assess', async (state) => {
      if (state.finding.category === 'secrets') {
        const analysis: Analysis = {
          kind: 'deterministic',
          assessment: 'needs_review',
          explanation:
            'Secret findings bypass model inference. Validate and rotate real credentials through a trusted manual process.',
          evidenceIds: state.finding.evidence.map((entry) => entry.id),
          limitations: [
            'Static patterns do not establish reachability or exploitability.',
            'Global authorization, RLS, runtime configuration and generated code may be outside the analyzed context.',
          ],
          inspectedFiles: state.inspectedFiles,
          contextIdsSent: state.contextIds,
          contextCharactersSent: state.context.length,
          contextTruncated: state.contextTruncated,
          rounds: state.rounds,
        };
        return { analysis, requestedContextIds: [], searchQueries: [] };
      }
      try {
        const broker = createContextBroker(snapshot, state.finding, profile, depth);
        broker.search(state.searchQueries);
        const assessment = await reviewer.assess(
          state.finding,
          state.context,
          broker.catalog,
          state.contextIds,
          {
            depth,
            rules: reviewRulesForFinding(state.finding),
            ...(signal ? { signal } : {}),
          },
        );
        const analysis: Analysis = {
          ...assessment,
          kind: reviewer.provider,
          inspectedFiles: state.inspectedFiles,
          contextTruncated: state.contextTruncated,
          rounds: state.rounds,
        };
        const allowedIds = new Set(broker.catalog.map((item) => item.id));
        const fresh = assessment.requestedContextIds.filter(
          (id) => allowedIds.has(id) && !state.contextIds.includes(id),
        );
        const searchable = broker.search(assessment.searchQueries, state.contextIds);
        return {
          analysis,
          requestedContextIds: fresh,
          searchQueries: searchable.length ? assessment.searchQueries : [],
        };
      } catch {
        return {
          analysis: {
            kind: reviewer.provider,
            assessment: 'inconclusive',
            explanation:
              'The local model was unavailable, exceeded its budget, or returned an invalid assessment. The scanner finding is preserved.',
            evidenceIds: state.finding.evidence.map((entry) => entry.id),
            limitations: [
              'Model assessment failed. No severity reduction or suppression was applied.',
            ],
            inspectedFiles: state.inspectedFiles,
            contextIdsSent: state.contextIds,
            contextCharactersSent: state.context.length,
            contextTruncated: state.contextTruncated,
            rounds: state.rounds,
          } satisfies Analysis,
          requestedContextIds: [],
          searchQueries: [],
        };
      }
    })
    .addEdge(START, 'collect_context')
    .addEdge('collect_context', 'assess')
    .addConditionalEdges('assess', (state) =>
      (state.requestedContextIds.length > 0 || state.searchQueries.length > 0) &&
      state.rounds < limits.maximumRounds
        ? 'collect_context'
        : END,
    )
    .compile();
}
