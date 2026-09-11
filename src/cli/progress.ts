import type { ScannerRun } from '../domain/types.ts';

export interface CliProgress {
  phase(message: string): void;
  scanners(runs: ScannerRun[]): void;
}

function duration(milliseconds: number): string {
  return milliseconds < 1_000
    ? `${milliseconds}ms`
    : `${(milliseconds / 1_000).toFixed(milliseconds < 10_000 ? 1 : 0)}s`;
}

export function createCliProgress(quiet: boolean, verbose: boolean): CliProgress {
  const write = (message: string) => {
    if (!quiet) console.error(message);
  };
  return {
    phase: (message) => write(`→ ${message}`),
    scanners: (runs) => {
      const elapsed = runs.reduce((total, run) => total + run.durationMs, 0);
      const completed = runs.filter((run) => run.status === 'completed').length;
      write(`✓ ${completed}/${runs.length} scanners completed · ${duration(elapsed)} scanner time`);
      const shown = [...runs]
        .sort((left, right) => right.durationMs - left.durationMs)
        .slice(0, verbose ? runs.length : 3);
      for (const run of shown)
        write(
          `  ${run.name}: ${duration(run.durationMs)} · ${run.status} · ${run.findings} finding(s)`,
        );
    },
  };
}
