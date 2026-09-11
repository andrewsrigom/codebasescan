export const agentReviewDepths = ['quick', 'standard', 'deep'] as const;
export type AgentReviewDepth = (typeof agentReviewDepths)[number];

export interface AgentReviewDepthLimit {
  maximumContextCharacters: number;
  maximumInitialItems: number;
  maximumRequestedItems: number;
  maximumCatalogItems: number;
  maximumSearchQueries: number;
  maximumSearchResults: number;
  maximumSearchCharacters: number;
  maximumRounds: number;
  maximumFindings: number;
  defaultMaximumCalls: number;
  defaultMaximumCallsPerFinding: number;
  defaultInputTokenBudget: number;
  defaultOutputTokenBudget: number;
  defaultMaximumOutputTokensPerCall: number;
}

export const agentReviewDepthLimits: Record<AgentReviewDepth, AgentReviewDepthLimit> = {
  quick: {
    maximumContextCharacters: 8_000,
    maximumInitialItems: 8,
    maximumRequestedItems: 1,
    maximumCatalogItems: 40,
    maximumSearchQueries: 0,
    maximumSearchResults: 0,
    maximumSearchCharacters: 0,
    maximumRounds: 1,
    maximumFindings: 6,
    defaultMaximumCalls: 6,
    defaultMaximumCallsPerFinding: 1,
    defaultInputTokenBudget: 60_000,
    defaultOutputTokenBudget: 5_000,
    defaultMaximumOutputTokensPerCall: 900,
  },
  standard: {
    maximumContextCharacters: 16_000,
    maximumInitialItems: 12,
    maximumRequestedItems: 2,
    maximumCatalogItems: 60,
    maximumSearchQueries: 2,
    maximumSearchResults: 4,
    maximumSearchCharacters: 3_000_000,
    maximumRounds: 2,
    maximumFindings: 12,
    defaultMaximumCalls: 12,
    defaultMaximumCallsPerFinding: 2,
    defaultInputTokenBudget: 120_000,
    defaultOutputTokenBudget: 10_000,
    defaultMaximumOutputTokensPerCall: 900,
  },
  deep: {
    maximumContextCharacters: 40_000,
    maximumInitialItems: 16,
    maximumRequestedItems: 4,
    maximumCatalogItems: 120,
    maximumSearchQueries: 2,
    maximumSearchResults: 8,
    maximumSearchCharacters: 12_000_000,
    maximumRounds: 4,
    maximumFindings: 24,
    defaultMaximumCalls: 32,
    defaultMaximumCallsPerFinding: 4,
    defaultInputTokenBudget: 320_000,
    defaultOutputTokenBudget: 30_000,
    defaultMaximumOutputTokensPerCall: 1_200,
  },
};

export function parseAgentReviewDepth(value: string | undefined): AgentReviewDepth {
  const depth = value?.trim() || 'standard';
  if (!agentReviewDepths.includes(depth as AgentReviewDepth))
    throw new Error('Agent review depth must be quick, standard, or deep.');
  return depth as AgentReviewDepth;
}
