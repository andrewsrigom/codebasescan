export const PIPELINE_START = '__pipeline_start__';
export const PIPELINE_END = '__pipeline_end__';

type PipelineBoundary = typeof PIPELINE_START | typeof PIPELINE_END;
type PipelineNode<State> = (state: Readonly<State>) => Promise<Partial<State>> | Partial<State>;

export interface CompiledPipeline<State, Input> {
  invoke(input: Input): Promise<State>;
}

export class DeterministicPipeline<State, Input> {
  private readonly nodes = new Map<string, PipelineNode<State>>();
  private readonly predecessors = new Map<string, Set<string>>();
  private readonly initialize: (input: Input) => State;
  private readonly merge: (state: State, update: Partial<State>) => State;

  constructor(
    initialize: (input: Input) => State,
    merge: (state: State, update: Partial<State>) => State,
  ) {
    this.initialize = initialize;
    this.merge = merge;
  }

  addNode(name: string, node: PipelineNode<State>): this {
    if (this.nodes.has(name)) throw new Error(`Pipeline node ${name} is already registered.`);
    this.nodes.set(name, node);
    this.predecessors.set(name, new Set());
    return this;
  }

  addEdge(from: string | string[], to: string | PipelineBoundary): this {
    if (to === PIPELINE_END) return this;
    const dependencies = this.predecessors.get(to);
    if (!dependencies) throw new Error(`Pipeline node ${to} is not registered.`);
    for (const source of Array.isArray(from) ? from : [from])
      if (source !== PIPELINE_START) dependencies.add(source);
    return this;
  }

  compile(): CompiledPipeline<State, Input> {
    const nodes = new Map(this.nodes);
    const predecessors = new Map(
      [...this.predecessors].map(([name, dependencies]) => [name, new Set(dependencies)]),
    );
    const initialize = this.initialize;
    const merge = this.merge;
    return {
      async invoke(input: Input): Promise<State> {
        let state = initialize(input);
        const completed = new Set<string>();
        while (completed.size < nodes.size) {
          const ready = [...nodes.keys()].filter(
            (name) =>
              !completed.has(name) &&
              [...(predecessors.get(name) ?? [])].every((dependency) => completed.has(dependency)),
          );
          if (!ready.length)
            throw new Error('The deterministic audit pipeline contains a cycle or missing node.');
          const snapshot = state;
          const updates = await Promise.all(
            ready.map(async (name) => ({ name, update: await nodes.get(name)!(snapshot) })),
          );
          for (const { name, update } of updates) {
            state = merge(state, update);
            completed.add(name);
          }
        }
        return state;
      },
    };
  }
}
