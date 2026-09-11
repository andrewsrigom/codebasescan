import { z } from 'zod';
import type { RuleQualityReport } from './rule-quality.ts';

const shortText = z.string().max(10_000);
const nonnegative = z.number().int().nonnegative();
const dispositionCounts = z.object({
  needs_review: nonnegative,
  confirmed: nonnegative,
  fixed: nonnegative,
  false_positive: nonnegative,
  accepted_risk: nonnegative,
});
const rule = z.object({
  id: shortText,
  source: z.enum([
    'builtin',
    'posture',
    'ast',
    'saas',
    'next',
    'react',
    'accessibility',
    'axe',
    'web',
    'privacy',
    'reliability',
    'environment',
    'supply-chain',
    'http-probe',
    'osv',
    'semgrep',
    'gitleaks',
  ]),
  ruleId: shortText,
  scanner: shortText,
  scannerVersion: shortText.optional(),
  detector: z.enum([
    'codebasescan-heuristic',
    'codebasescan-ast',
    'scanner',
    'runtime-probe',
    'advisory-database',
  ]),
  categories: z.array(shortText).max(100),
  supportedFrameworks: z.array(shortText).max(100),
  standards: z.array(z.object({ family: z.enum(['CWE', 'WCAG']), id: shortText })).max(100),
  declaredFixtureMetrics: z.object({
    status: z.enum(['measured', 'known_false_positive', 'not_measured']),
    truePositives: nonnegative,
    falsePositives: nonnegative,
    falseNegatives: nonnegative,
    scope: shortText,
  }),
  observedFindings: nonnegative,
  humanDispositions: dispositionCounts,
  limitations: z.array(shortText).max(100),
  calibratedWith: shortText,
});

const schema = z.object({
  schemaVersion: z.literal(3),
  kind: z.literal('codebasescan-rule-quality'),
  generatedAt: shortText,
  auditId: shortText,
  summary: z.object({
    appliedRules: nonnegative,
    fixtureMeasured: nonnegative,
    fixtureKnownFalsePositive: nonnegative,
    withHumanDisposition: nonnegative,
  }),
  rules: z.array(rule).max(10_000),
  limitations: z.array(shortText).max(100),
});

export function parseRuleQualityReport(value: unknown): RuleQualityReport {
  return schema.parse(value) as RuleQualityReport;
}

export function ruleQualityJsonSchema(): unknown {
  return z.toJSONSchema(schema, { target: 'draft-07', unrepresentable: 'throw' });
}
