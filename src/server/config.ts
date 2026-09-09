import path from 'node:path';
export interface Configuration {
  dataDirectory: string;
  databasePath: string;
  checkpointPath: string;
  temporaryDirectory: string;
  rulesDirectory: string;
  aiMode: 'disabled' | 'ollama';
  model: string;
  semgrep: boolean;
  gitleaks: boolean;
}
export function configuration(): Configuration {
  const dataDirectory = path.resolve(process.env.TRACEWARD_DATA_DIR || '.traceward');
  const aiMode = process.env.TRACEWARD_AI === 'ollama' ? 'ollama' : 'disabled';
  if (process.env.TRACEWARD_AI && !['disabled', 'ollama'].includes(process.env.TRACEWARD_AI))
    throw new Error('TRACEWARD_AI must be disabled or ollama.');
  const model = process.env.OLLAMA_MODEL?.trim() ?? '';
  if (aiMode === 'ollama' && !model)
    throw new Error('Set OLLAMA_MODEL to an already downloaded local model.');
  return {
    dataDirectory, databasePath: path.join(dataDirectory, 'application.sqlite'),
    checkpointPath: path.join(dataDirectory, 'checkpoints.sqlite'),
    temporaryDirectory: path.join(dataDirectory, 'temporary'),
    rulesDirectory: path.resolve('configs'), aiMode, model,
    semgrep: process.env.TRACEWARD_SEMGREP === 'true',
    gitleaks: process.env.TRACEWARD_GITLEAKS === 'true',
  };
}
