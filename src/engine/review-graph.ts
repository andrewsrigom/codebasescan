import { Annotation, END, START, StateGraph } from '@langchain/langgraph';
import type { Analysis, Finding, Snapshot } from '../domain/types.ts';
import type { Reviewer } from './model.ts';
import { createReadSourceTool } from './model.ts';
const ReviewState = Annotation.Root({
  finding: Annotation<Finding>(),
  inspectedFiles: Annotation<string[]>({ reducer: (_, value) => value, default: () => [] }),
  requestedFiles: Annotation<string[]>({ reducer: (_, value) => value, default: () => [] }),
  context: Annotation<string>({ reducer: (_, value) => value, default: () => '' }),
  rounds: Annotation<number>({ reducer: (_, value) => value, default: () => 0 }),
  analysis: Annotation<Analysis | null>({ reducer: (_, value) => value, default: () => null }),
});
export function buildReviewGraph(
  snapshot: Snapshot,
  reviewer: Reviewer | null,
  signal?: AbortSignal,
) {
  const readSource = createReadSourceTool(snapshot);
  return new StateGraph(ReviewState)
    .addNode('collect_context', async (state) => {
      const paths = state.requestedFiles.length
        ? state.requestedFiles
        : state.finding.evidence.map((entry) => entry.file);
      const fresh = [...new Set(paths)]
        .filter((file) => !state.inspectedFiles.includes(file))
        .slice(0, 2);
      const chunks: string[] = [];
      for (const file of fresh) chunks.push(String(await readSource.invoke({ file })));
      return {
        context: `${state.context}\n${chunks.join('\n')}`.slice(0, 30000),
        inspectedFiles: [...state.inspectedFiles, ...fresh],
        rounds: state.rounds + 1,
      };
    })
    .addNode('assess', async (state) => {
      if (!reviewer || state.finding.category === 'secrets') {
        const analysis: Analysis = {
          kind: 'deterministic',
          assessment: 'needs_review',
          explanation:
            state.finding.category === 'secrets'
              ? 'Secret findings bypass model inference. Validate and rotate real credentials through a trusted manual process.'
              : 'The scanner produced a review candidate. No LLM-based verification was performed.',
          evidenceIds: state.finding.evidence.map((entry) => entry.id),
          limitations: [
            'Static patterns do not establish reachability or exploitability.',
            'Global authorization, RLS, runtime configuration and generated code may be outside the analyzed context.',
          ],
          inspectedFiles: state.inspectedFiles,
          rounds: state.rounds,
        };
        return { analysis, requestedFiles: [] };
      }
      try {
        const assessment = await reviewer.assess(
          state.finding,
          state.context,
          snapshot.files.map((file) => file.path).slice(0, 300),
          state.inspectedFiles,
          signal,
        );
        const analysis: Analysis = {
          ...assessment,
          kind: reviewer.provider,
          inspectedFiles: state.inspectedFiles,
          rounds: state.rounds,
        };
        const fresh = assessment.requestedFiles.filter(
          (file) => !state.inspectedFiles.includes(file),
        );
        return { analysis, requestedFiles: fresh };
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
            rounds: state.rounds,
          } satisfies Analysis,
          requestedFiles: [],
        };
      }
    })
    .addEdge(START, 'collect_context')
    .addEdge('collect_context', 'assess')
    .addConditionalEdges('assess', (state) =>
      state.requestedFiles.length > 0 && state.rounds < 2 ? 'collect_context' : END,
    )
    .compile();
}
