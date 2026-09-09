export function disableRemoteTracing(): void {
  process.env.LANGSMITH_TRACING = 'false';
  process.env.LANGCHAIN_TRACING_V2 = 'false';
  process.env.LANGCHAIN_TRACING = 'false';
  process.env.NEXT_TELEMETRY_DISABLED = '1';
  delete process.env.LANGSMITH_API_KEY;
  delete process.env.LANGCHAIN_API_KEY;
}
