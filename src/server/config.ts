import path from 'node:path';
import { fileURLToPath } from 'node:url';

const bundledRulesDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'configs',
);
export interface Configuration {
  dataDirectory: string;
  databasePath: string;
  temporaryDirectory: string;
  rulesDirectory: string;
  semgrep: boolean;
  gitleaks: boolean;
  osv: boolean;
  osvCacheHours: number;
  advisoryDatabasePath: string;
  scannerCache?: boolean;
  scannerCacheDirectory?: string;
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
export function configuration(): Configuration {
  const dataDirectory = path.resolve(
    /* turbopackIgnore: true */ process.env.CODEBASESCAN_DATA_DIR || '.codebasescan',
  );
  return {
    dataDirectory,
    databasePath: path.join(dataDirectory, 'application.sqlite'),
    temporaryDirectory: path.join(dataDirectory, 'temporary'),
    rulesDirectory: process.env.CODEBASESCAN_RULES_DIR
      ? path.resolve(process.env.CODEBASESCAN_RULES_DIR)
      : bundledRulesDirectory,
    semgrep: process.env.CODEBASESCAN_SEMGREP === 'true',
    gitleaks: process.env.CODEBASESCAN_GITLEAKS === 'true',
    osv: process.env.CODEBASESCAN_OSV === 'true',
    osvCacheHours: boundedInteger(process.env.CODEBASESCAN_OSV_CACHE_HOURS, 24, 1, 720),
    advisoryDatabasePath: path.resolve(
      /* turbopackIgnore: true */
      process.env.CODEBASESCAN_ADVISORY_DB || path.join(dataDirectory, 'advisory-database.json'),
    ),
    scannerCache: process.env.CODEBASESCAN_SCANNER_CACHE !== 'false',
  };
}
