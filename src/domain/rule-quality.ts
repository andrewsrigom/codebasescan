import type { AuditReport, Finding } from './types.ts';

export const ruleQualityVersion = 3 as const;

export interface RuleQualityEntry {
  id: string;
  source: Finding['source'];
  ruleId: string;
  scanner: string;
  scannerVersion?: string;
  detector: NonNullable<Finding['provenance']>['detector'];
  categories: Finding['category'][];
  supportedFrameworks: string[];
  standards: { family: 'CWE' | 'WCAG'; id: string }[];
  declaredFixtureMetrics: {
    status: 'measured' | 'known_false_positive' | 'not_measured';
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    scope: string;
  };
  observedFindings: number;
  humanDispositions: Record<Finding['disposition'], number>;
  limitations: string[];
  calibratedWith: string;
}

export interface RuleQualityReport {
  schemaVersion: typeof ruleQualityVersion;
  kind: 'codebasescan-rule-quality';
  generatedAt: string;
  auditId: string;
  summary: {
    appliedRules: number;
    fixtureMeasured: number;
    fixtureKnownFalsePositive: number;
    withHumanDisposition: number;
  };
  rules: RuleQualityEntry[];
  limitations: string[];
}

export const declaredFixtureRuleKeys = [
  ...Array.from({ length: 10 }, (_, index) => `ast:TW-AST${String(index + 1).padStart(3, '0')}`),
  'ast:TW-AST018',
  ...Array.from({ length: 7 }, (_, index) => `next:TW-NEXT${String(index + 1).padStart(3, '0')}`),
  ...Array.from({ length: 9 }, (_, index) => `react:TW-REACT${String(index + 1).padStart(3, '0')}`),
  ...Array.from({ length: 9 }, (_, index) => `saas:TW-SAAS${String(index + 1).padStart(3, '0')}`),
  ...Array.from(
    { length: 4 },
    (_, index) => `accessibility:TW-A11Y${String(index + 1).padStart(3, '0')}`,
  ),
  ...Array.from(
    { length: 3 },
    (_, index) => `privacy:TW-PRIV${String(index + 1).padStart(3, '0')}`,
  ),
  ...Array.from(
    { length: 2 },
    (_, index) => `reliability:TW-REL${String(index + 1).padStart(3, '0')}`,
  ),
  'environment:TW-ENV001',
  'builtin:TW-001',
  'builtin:TW-003',
  'builtin:TW-005',
  'builtin:TW-006',
  'builtin:TW-007',
  'posture:TW-P001',
  'posture:TW-P003',
  'posture:TW-P004',
  'posture:TW-P006',
] as const;

const benchmarked = new Set<string>(declaredFixtureRuleKeys);

const frameworks: Partial<Record<Finding['source'], string[]>> = {
  ast: ['Node.js', 'TypeScript', 'Next.js'],
  saas: ['Node.js', 'TypeScript', 'Next.js SaaS'],
  next: ['Next.js'],
  react: ['React', 'Next.js'],
  accessibility: ['React JSX', 'Next.js'],
  axe: ['Axe JSON result format'],
  web: ['React', 'Next.js'],
  privacy: ['Node.js', 'React', 'Next.js'],
  reliability: ['Node.js', 'Next.js request boundaries'],
  environment: ['Node.js', 'Next.js', 'Vite'],
  posture: ['Node.js', 'Next.js'],
  'supply-chain': ['npm', 'pnpm', 'Yarn'],
  osv: ['npm', 'pnpm', 'Yarn'],
};

const limitations: Partial<Record<Finding['source'], string[]>> = {
  builtin: ['Regex heuristic; comments and indirect flows can change the result.'],
  posture: ['Declared configuration is not proof of effective runtime behavior.'],
  ast: ['Syntax-only bounded call relationships are not full type-aware data flow.'],
  saas: ['Business semantics, provider settings, and database policy require external evidence.'],
  next: ['Middleware, deployment policy, and runtime cache behavior may be outside the snapshot.'],
  react: ['Runtime values and browser behavior are not executed.'],
  accessibility: [
    'Focus order, contrast, layout, and assistive-technology behavior are not tested.',
  ],
  axe: [
    'Imported Axe results reflect only pages, states, browsers, and rules exercised externally.',
  ],
  web: ['Source declarations do not prove deployed crawler, metadata, or indexing behavior.'],
  privacy: [
    'Purpose, consent, retention, deletion, and actual third-party transfer are unverified.',
  ],
  reliability: ['Platform timeouts, retries, queues, and recovery behavior may be external.'],
  environment: [
    'Deployment-provided names and dynamic environment access can remain outside captured templates.',
  ],
  'supply-chain': ['A declaration is a review candidate, not proof of compromise.'],
  'http-probe': ['One response does not establish whole-application runtime behavior.'],
  osv: ['Package presence and source-reference hints do not prove vulnerable code execution.'],
  semgrep: ['Coverage depends on the installed scanner and selected fixed CodebaseScan rules.'],
  gitleaks: ['Secret-shaped matches require validity and exposure review.'],
};

const wcag: Record<string, string[]> = {
  'TW-A11Y001': ['1.1.1'],
  'TW-A11Y002': ['2.1.1', '4.1.2'],
  'TW-A11Y003': ['3.1.1'],
  'TW-A11Y004': ['1.3.1', '3.3.2', '4.1.2'],
  'TW-A11Y005': ['4.1.2'],
  'TW-A11Y006': ['2.1.1', '4.1.2'],
};

function dispositionCounts(findings: Finding[]): Record<Finding['disposition'], number> {
  return {
    needs_review: findings.filter((finding) => finding.disposition === 'needs_review').length,
    confirmed: findings.filter((finding) => finding.disposition === 'confirmed').length,
    fixed: findings.filter((finding) => finding.disposition === 'fixed').length,
    false_positive: findings.filter((finding) => finding.disposition === 'false_positive').length,
    accepted_risk: findings.filter((finding) => finding.disposition === 'accepted_risk').length,
  };
}

function fixtureMetrics(
  source: Finding['source'],
  ruleId: string,
): RuleQualityEntry['declaredFixtureMetrics'] {
  const key = `${source}:${ruleId}`;
  return benchmarked.has(key)
    ? {
        status: 'measured',
        truePositives: 1,
        falsePositives: 0,
        falseNegatives: 0,
        scope: 'Declared inert fixtures only.',
      }
    : {
        status: 'not_measured',
        truePositives: 0,
        falsePositives: 0,
        falseNegatives: 0,
        scope: 'No per-rule declared benchmark result is published.',
      };
}

export function buildRuleQualityReport(report: AuditReport): RuleQualityReport {
  const groups = new Map<string, Finding[]>();
  for (const finding of report.findings) {
    const key = `${finding.source}:${finding.ruleId}`;
    groups.set(key, [...(groups.get(key) ?? []), finding]);
  }
  const rules = [...groups.entries()]
    .map(([id, findings]): RuleQualityEntry => {
      const first = findings[0]!;
      const scanner = first.provenance?.scanner ?? first.source;
      const scannerVersion = first.provenance?.scannerVersion;
      return {
        id,
        source: first.source,
        ruleId: first.ruleId,
        scanner,
        ...(scannerVersion ? { scannerVersion } : {}),
        detector: first.provenance?.detector ?? 'codebasescan-heuristic',
        categories: [...new Set(findings.map((finding) => finding.category))],
        supportedFrameworks: frameworks[first.source] ?? ['JavaScript/TypeScript source'],
        standards: [...new Set(findings.flatMap((finding) => finding.cwe))].map((id) => ({
          family: 'CWE' as const,
          id,
        })),
        declaredFixtureMetrics: fixtureMetrics(first.source, first.ruleId),
        observedFindings: findings.length,
        humanDispositions: dispositionCounts(findings),
        limitations: limitations[first.source] ?? ['Review exact evidence and scanner coverage.'],
        calibratedWith: scannerVersion ?? 'unversioned-scanner-result',
      };
    })
    .map((entry) => ({
      ...entry,
      standards: [
        ...entry.standards,
        ...(wcag[entry.ruleId] ?? []).map((id) => ({ family: 'WCAG' as const, id })),
      ],
    }))
    .sort((left, right) => left.id.localeCompare(right.id));
  return {
    schemaVersion: ruleQualityVersion,
    kind: 'codebasescan-rule-quality',
    generatedAt: report.createdAt,
    auditId: report.auditId,
    summary: {
      appliedRules: rules.length,
      fixtureMeasured: rules.filter((rule) => rule.declaredFixtureMetrics.status === 'measured')
        .length,
      fixtureKnownFalsePositive: rules.filter(
        (rule) => rule.declaredFixtureMetrics.status === 'known_false_positive',
      ).length,
      withHumanDisposition: rules.filter((rule) =>
        Object.entries(rule.humanDispositions).some(
          ([decision, count]) => decision !== 'needs_review' && count > 0,
        ),
      ).length,
    },
    rules,
    limitations: [
      'Fixture metrics describe declared inert cases, not production accuracy.',
      'Only rules represented in this audit are included; zero-hit rule inventory remains a pack-level artifact.',
      'Standards mappings aid review and do not establish compliance or exploitability.',
      'Real-project dispositions require independent human review before accuracy claims.',
    ],
  };
}
