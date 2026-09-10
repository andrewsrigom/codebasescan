import path from 'node:path';
import os from 'node:os';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { z } from 'zod';
import { captureSnapshot } from '../src/security/paths.ts';
import { scanPatterns } from '../src/scanners/builtin.ts';
import { scanPosture } from '../src/scanners/posture.ts';
import { scanOsv } from '../src/scanners/osv.ts';
import { profileProject } from '../src/scanners/project-profile.ts';
import { scanAstSecurity } from '../src/scanners/ast-security.ts';
import { scanNextSecurity } from '../src/scanners/next-security.ts';
import { scanReactSecurity } from '../src/scanners/react-security.ts';
import { scanSaasSecurity } from '../src/scanners/saas-security.ts';

const truthSchema = z.object({
  id: z.string(),
  category: z.string(),
  scanners: z.array(z.enum(['builtin', 'posture', 'ast', 'saas', 'next', 'react', 'osv'])),
  expectedRuleIds: z.array(z.string()),
});

async function truthFiles(directory: string): Promise<string[]> {
  const output: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...(await truthFiles(target)));
    else if (entry.name === 'ground-truth.json') output.push(target);
  }
  return output.sort();
}

const osvFixtureFetch: typeof fetch = async (input, init) => {
  const url = String(input);
  if (url.endsWith('/querybatch')) {
    const body = JSON.parse(String(init?.body ?? '{}')) as { queries?: unknown[] };
    return Response.json({
      results: (body.queries ?? []).map(() => ({ vulns: [{ id: 'GHSA-benchmark-fixture' }] })),
    });
  }
  return Response.json({
    id: 'GHSA-benchmark-fixture',
    summary: 'Deterministic benchmark advisory',
    modified: '2026-01-01T00:00:00Z',
    affected: [
      {
        package: { name: 'fixture-package' },
        ecosystem_specific: { severity: 'HIGH' },
        ranges: [{ events: [{ introduced: '0' }, { fixed: '1.0.1' }] }],
      },
    ],
  });
};

const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-benchmark-'));
let truePositives = 0;
let falsePositives = 0;
let falseNegatives = 0;
let astTruePositives = 0;
let astFalsePositives = 0;
let astFalseNegatives = 0;
let nextTruePositives = 0;
let nextFalsePositives = 0;
let nextFalseNegatives = 0;
let reactTruePositives = 0;
let reactFalsePositives = 0;
let reactFalseNegatives = 0;
let saasTruePositives = 0;
let saasFalsePositives = 0;
let saasFalseNegatives = 0;
try {
  for (const truthFile of await truthFiles(path.resolve('benchmarks'))) {
    const truth = truthSchema.parse(JSON.parse(await readFile(truthFile, 'utf8')) as unknown);
    const source = await captureSnapshot(path.dirname(truthFile));
    const profile = profileProject(source).profile;
    const findings = [
      ...(truth.scanners.includes('builtin') ? scanPatterns(source) : []),
      ...(truth.scanners.includes('posture') ? scanPosture(source) : []),
      ...(truth.scanners.includes('ast') ? scanAstSecurity(source, profile).findings : []),
      ...(truth.scanners.includes('saas') ? scanSaasSecurity(source, profile).findings : []),
      ...(truth.scanners.includes('next') ? scanNextSecurity(source, profile).findings : []),
      ...(truth.scanners.includes('react') ? scanReactSecurity(source, profile).findings : []),
    ];
    if (truth.scanners.includes('osv')) {
      const osv = await scanOsv(
        source,
        true,
        path.join(temporary, `${truth.id}.json`),
        24,
        undefined,
        { fetch: osvFixtureFetch, now: () => Date.parse('2026-01-02T00:00:00Z') },
      );
      findings.push(...osv.findings);
    }
    const actual = [...new Set(findings.map((finding) => finding.ruleId))].sort();
    const expected = [...new Set(truth.expectedRuleIds)].sort();
    const truePositive = actual.filter((rule) => expected.includes(rule)).length;
    const falsePositive = actual.filter((rule) => !expected.includes(rule)).length;
    const falseNegative = expected.filter((rule) => !actual.includes(rule)).length;
    truePositives += truePositive;
    falsePositives += falsePositive;
    falseNegatives += falseNegative;
    if (truth.scanners.length === 1 && truth.scanners[0] === 'ast') {
      astTruePositives += truePositive;
      astFalsePositives += falsePositive;
      astFalseNegatives += falseNegative;
    }
    if (truth.scanners.length === 1 && truth.scanners[0] === 'next') {
      nextTruePositives += truePositive;
      nextFalsePositives += falsePositive;
      nextFalseNegatives += falseNegative;
    }
    if (truth.scanners.length === 1 && truth.scanners[0] === 'react') {
      reactTruePositives += truePositive;
      reactFalsePositives += falsePositive;
      reactFalseNegatives += falseNegative;
    }
    if (truth.scanners.length === 1 && truth.scanners[0] === 'saas') {
      saasTruePositives += truePositive;
      saasFalsePositives += falsePositive;
      saasFalseNegatives += falseNegative;
    }
    console.log(
      JSON.stringify({
        id: truth.id,
        category: truth.category,
        expected,
        actual,
        truePositives: truePositive,
        falsePositives: falsePositive,
        falseNegatives: falseNegative,
      }),
    );
  }
} finally {
  await rm(temporary, { recursive: true, force: true });
}

const precision = truePositives / Math.max(1, truePositives + falsePositives);
const recall = truePositives / Math.max(1, truePositives + falseNegatives);
const astPrecision = astTruePositives / Math.max(1, astTruePositives + astFalsePositives);
const astRecall = astTruePositives / Math.max(1, astTruePositives + astFalseNegatives);
const nextPrecision = nextTruePositives / Math.max(1, nextTruePositives + nextFalsePositives);
const nextRecall = nextTruePositives / Math.max(1, nextTruePositives + nextFalseNegatives);
const reactPrecision = reactTruePositives / Math.max(1, reactTruePositives + reactFalsePositives);
const reactRecall = reactTruePositives / Math.max(1, reactTruePositives + reactFalseNegatives);
const saasPrecision = saasTruePositives / Math.max(1, saasTruePositives + saasFalsePositives);
const saasRecall = saasTruePositives / Math.max(1, saasTruePositives + saasFalseNegatives);
console.log(
  JSON.stringify({
    summary: {
      truePositives,
      falsePositives,
      falseNegatives,
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      ast: {
        truePositives: astTruePositives,
        falsePositives: astFalsePositives,
        falseNegatives: astFalseNegatives,
        precision: Number(astPrecision.toFixed(4)),
        recall: Number(astRecall.toFixed(4)),
      },
      next: {
        truePositives: nextTruePositives,
        falsePositives: nextFalsePositives,
        falseNegatives: nextFalseNegatives,
        precision: Number(nextPrecision.toFixed(4)),
        recall: Number(nextRecall.toFixed(4)),
      },
      react: {
        truePositives: reactTruePositives,
        falsePositives: reactFalsePositives,
        falseNegatives: reactFalseNegatives,
        precision: Number(reactPrecision.toFixed(4)),
        recall: Number(reactRecall.toFixed(4)),
      },
      saas: {
        truePositives: saasTruePositives,
        falsePositives: saasFalsePositives,
        falseNegatives: saasFalseNegatives,
        precision: Number(saasPrecision.toFixed(4)),
        recall: Number(saasRecall.toFixed(4)),
      },
    },
  }),
);
console.log(
  'Benchmark measures Traceward rules on declared ground truth. It is not a security certification or a generic model evaluation.',
);
process.exitCode =
  precision >= 0.85 &&
  recall >= 0.95 &&
  astPrecision >= 0.9 &&
  astRecall >= 0.85 &&
  nextPrecision >= 0.9 &&
  nextRecall >= 0.85 &&
  reactPrecision >= 0.9 &&
  reactRecall >= 0.85 &&
  saasPrecision >= 0.9 &&
  saasRecall >= 0.85
    ? 0
    : 1;
