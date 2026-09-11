import path from 'node:path';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { format as formatDocument, resolveConfig as resolvePrettierConfig } from 'prettier';
import { parseAuditReport } from '../src/domain/report-schema.ts';
import { parseCalibrationLedger } from '../src/domain/calibration-schema.ts';
import { buildPublicDemo, type PublicDemoReplacement } from '../src/reporting/public-demo.ts';

interface Arguments {
  report?: string;
  calibration?: string;
  output: string;
  name: string;
  replacements: PublicDemoReplacement[];
}

function parseArguments(values: string[]): Arguments {
  const result: Arguments = {
    output: 'public-demo',
    name: 'Example SaaS Application',
    replacements: [],
  };
  for (let index = 0; index < values.length; index += 1) {
    const option = values[index];
    const value = values[index + 1];
    if (!value) throw new Error(`Missing value for ${option}.`);
    if (option === '--report') result.report = value;
    else if (option === '--calibration') result.calibration = value;
    else if (option === '--output') result.output = value;
    else if (option === '--name') result.name = value;
    else if (option === '--replace') {
      const separator = value.indexOf('=');
      if (separator < 1 || separator === value.length - 1)
        throw new Error('Use --replace original=replacement.');
      result.replacements.push({
        from: value.slice(0, separator),
        to: value.slice(separator + 1),
      });
    } else throw new Error(`Unknown option: ${option}.`);
    index += 1;
  }
  return result;
}

const input = parseArguments(process.argv.slice(2));
if (!input.report || !input.calibration) {
  throw new Error(
    'Usage: npm run demo:public -- --report <audit-report.json> --calibration <ledger.json> [--replace original=replacement]',
  );
}

const report = parseAuditReport(
  JSON.parse(await readFile(path.resolve(input.report), 'utf8')) as unknown,
);
const ledger = parseCalibrationLedger(
  JSON.parse(await readFile(path.resolve(input.calibration), 'utf8')) as unknown,
);
const demo = buildPublicDemo(report, ledger, {
  projectName: input.name,
  replacements: input.replacements,
});

const forbidden = [
  report.projectName,
  ...input.replacements.map((replacement) => replacement.from),
];
for (const value of forbidden) {
  if (demo.html.toLowerCase().includes(value.toLowerCase()))
    throw new Error(`Public demo still contains a forbidden identifier: ${value}`);
}

const output = path.resolve(input.output);
const outputFile = path.join(output, 'index.html');
const prettierConfig = (await resolvePrettierConfig(outputFile)) ?? {};
await mkdir(output, { recursive: true });
await writeFile(
  outputFile,
  await formatDocument(demo.html, { ...prettierConfig, filepath: outputFile }),
  { mode: 0o644 },
);
console.log(`Wrote ${demo.retainedFindings} retained findings to ${outputFile}`);
