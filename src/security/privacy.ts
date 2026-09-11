export function disableTelemetry(): void {
  process.env.NEXT_TELEMETRY_DISABLED = '1';
}
