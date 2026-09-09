import path from 'node:path';
export interface Configuration {
  dataDirectory: string;
  databasePath: string;
  checkpointPath: string;
  temporaryDirectory: string;
  rulesDirectory: string;
  aiMode: 'disabled' | 'ollama' | 'openai';
  model: string;
  strongModel: string;
  openaiApiKey?: string;
  aiTimeoutMs: number;
  aiMaxRetries: number;
  aiMaxCalls: number;
  aiMaxCallsPerFinding: number;
  aiInputTokenBudget: number;
  aiOutputTokenBudget: number;
  aiMaxOutputTokensPerCall: number;
  openaiInputCostPerMillion?: number;
  openaiOutputCostPerMillion?: number;
  semgrep: boolean;
  gitleaks: boolean;
  osv: boolean;
  osvCacheHours: number;
}
function boundedInteger(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
) {
  if (value === undefined || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum)
    throw new Error(`Expected an integer between ${minimum} and ${maximum}.`);
  return parsed;
}
function optionalNumber(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 10000)
    throw new Error('OpenAI token prices must be numbers between 0 and 10000.');
  return parsed;
}
export function configuration(): Configuration {
  const dataDirectory = path.resolve(
    /* turbopackIgnore: true */ process.env.TRACEWARD_DATA_DIR || '.traceward',
  );
  const requestedAiMode = process.env.TRACEWARD_AI ?? 'disabled';
  if (!['disabled', 'ollama', 'openai'].includes(requestedAiMode))
    throw new Error('TRACEWARD_AI must be disabled, ollama, or openai.');
  const aiMode = requestedAiMode as Configuration['aiMode'];
  const model =
    aiMode === 'ollama'
      ? (process.env.OLLAMA_MODEL?.trim() ?? '')
      : aiMode === 'openai'
        ? (process.env.OPENAI_MODEL?.trim() ?? '')
        : '';
  if (aiMode === 'ollama' && !model)
    throw new Error('Set OLLAMA_MODEL to an already downloaded local model.');
  const openaiApiKey = process.env.OPENAI_API_KEY?.trim();
  if (aiMode === 'openai' && (!model || !openaiApiKey))
    throw new Error('Set OPENAI_MODEL and OPENAI_API_KEY before enabling OpenAI analysis.');
  return {
    dataDirectory,
    databasePath: path.join(dataDirectory, 'application.sqlite'),
    checkpointPath: path.join(dataDirectory, 'checkpoints.sqlite'),
    temporaryDirectory: path.join(dataDirectory, 'temporary'),
    rulesDirectory: path.resolve('configs'),
    aiMode,
    model,
    strongModel: process.env.OPENAI_STRONG_MODEL?.trim() ?? '',
    ...(openaiApiKey ? { openaiApiKey } : {}),
    aiTimeoutMs: boundedInteger(process.env.TRACEWARD_AI_TIMEOUT_MS, 30000, 1000, 120000),
    aiMaxRetries: boundedInteger(process.env.TRACEWARD_AI_MAX_RETRIES, 1, 0, 3),
    aiMaxCalls: boundedInteger(process.env.TRACEWARD_AI_MAX_CALLS, 12, 1, 100),
    aiMaxCallsPerFinding: boundedInteger(process.env.TRACEWARD_AI_MAX_CALLS_PER_FINDING, 2, 1, 3),
    aiInputTokenBudget: boundedInteger(
      process.env.TRACEWARD_AI_INPUT_TOKEN_BUDGET,
      120000,
      1000,
      2000000,
    ),
    aiOutputTokenBudget: boundedInteger(
      process.env.TRACEWARD_AI_OUTPUT_TOKEN_BUDGET,
      10000,
      100,
      200000,
    ),
    aiMaxOutputTokensPerCall: boundedInteger(
      process.env.TRACEWARD_AI_MAX_OUTPUT_TOKENS_PER_CALL,
      900,
      100,
      10000,
    ),
    openaiInputCostPerMillion: optionalNumber(process.env.OPENAI_INPUT_COST_PER_MTOK),
    openaiOutputCostPerMillion: optionalNumber(process.env.OPENAI_OUTPUT_COST_PER_MTOK),
    semgrep: process.env.TRACEWARD_SEMGREP === 'true',
    gitleaks: process.env.TRACEWARD_GITLEAKS === 'true',
    osv: process.env.TRACEWARD_OSV === 'true',
    osvCacheHours: boundedInteger(process.env.TRACEWARD_OSV_CACHE_HOURS, 24, 1, 720),
  };
}
