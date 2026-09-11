import { buildCalibrationReport, type CalibrationLedger } from '../domain/calibration.ts';
import { parseAuditReport } from '../domain/report-schema.ts';
import { buildRemediationPlan } from '../domain/remediation.ts';
import { parseRemediationPlan } from '../domain/remediation-schema.ts';
import { digest } from '../domain/findings.ts';
import { toHtml } from '../domain/reports.ts';
import type { AuditReport } from '../domain/types.ts';

export interface PublicDemoReplacement {
  from: string;
  to: string;
}

export interface PublicDemoOptions {
  projectName: string;
  replacements?: PublicDemoReplacement[];
}

export interface PublicDemoResult {
  report: AuditReport;
  html: string;
  retainedFindings: number;
}

function escapedPattern(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function replacementList(report: AuditReport, options: PublicDemoOptions): PublicDemoReplacement[] {
  const replacements = [
    { from: report.projectName, to: options.projectName },
    ...(options.replacements ?? []),
  ];
  for (const replacement of replacements) {
    if (!replacement.from.trim()) throw new Error('Public demo replacements cannot be empty.');
    if (!replacement.to.trim()) throw new Error('Public demo replacement values cannot be empty.');
  }
  return replacements.sort((left, right) => right.from.length - left.from.length);
}

function replaceText(value: string, replacements: PublicDemoReplacement[]): string {
  return replacements.reduce(
    (current, replacement) =>
      current.replace(new RegExp(escapedPattern(replacement.from), 'gi'), replacement.to),
    value,
  );
}

function anonymize(value: unknown, replacements: PublicDemoReplacement[]): unknown {
  if (typeof value === 'string') return replaceText(value, replacements);
  if (Array.isArray(value)) return value.map((item) => anonymize(item, replacements));
  if (typeof value !== 'object' || value === null) return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, anonymize(item, replacements)]),
  );
}

function publicAuditId(snapshotDigest: string): string {
  return `00000000-0000-4000-8000-${digest(`public-demo:\0${snapshotDigest}`).slice(0, 12)}`;
}

function publicDemoReport(
  source: AuditReport,
  ledger: CalibrationLedger,
  options: PublicDemoOptions,
): AuditReport {
  buildCalibrationReport([{ report: source, ledger }]);
  const retainedFingerprints = new Set(
    ledger.entries
      .filter((entry) => entry.outcome === 'true_positive')
      .map((entry) => entry.fingerprint),
  );
  if (!retainedFingerprints.size)
    throw new Error('Public demo requires at least one retained finding.');

  const findings = source.findings.filter((finding) =>
    retainedFingerprints.has(finding.fingerprint),
  );
  if (findings.length !== retainedFingerprints.size)
    throw new Error('A retained calibration entry no longer matches the source report.');

  const replacements = replacementList(source, options);
  const sanitized = anonymize(
    {
      ...source,
      auditId: publicAuditId(source.snapshotDigest),
      projectName: options.projectName,
      snapshotDigest: digest(`public-demo:\0${source.snapshotDigest}`),
      findings,
      riskCorrelation: undefined,
      reviewImport: undefined,
      suppressionImport: undefined,
      limitations: [
        ...source.limitations,
        'This public example is anonymized and curated from an authorized real repository.',
        'Only candidates retained by a model-assisted static source review are shown. Independent human validation and runtime testing were not performed.',
      ],
      publication: 'draft',
    },
    replacements,
  );
  return parseAuditReport(sanitized);
}

function addPublicDisclosure(html: string, retainedFindings: number): string {
  const css =
    '.public-demo-note{margin-top:14px;border:1px solid #244d8d;background:#0d1b33;border-radius:12px;padding:14px 15px;color:#c9d8f5}.public-demo-note strong{display:block;color:#fff;font-size:12px}.public-demo-note p{margin:6px 0 0;font-size:11px;color:#9fb2d4}';
  const disclosure =
    '<aside class="public-demo-note"><strong>Anonymized public example</strong><p>Generated from an authorized real repository. This curated view retains ' +
    retainedFindings +
    ' candidates after model-assisted source review. It is not a certification or a substitute for human validation.</p></aside>';
  const withCss = html.replace('</style>', css + '</style>');
  const overviewEnd = '</section><section id="risks"';
  if (!withCss.includes(overviewEnd)) throw new Error('Public demo insertion point is missing.');
  return withCss
    .replace(overviewEnd, disclosure + overviewEnd)
    .replace('<span>Audits</span><span>›</span>', '<span>Public example</span><span>›</span>')
    .replace('Local static review', 'Public example report');
}

export function buildPublicDemo(
  source: AuditReport,
  ledger: CalibrationLedger,
  options: PublicDemoOptions,
): PublicDemoResult {
  const report = publicDemoReport(source, ledger, options);
  const remediationPlan = parseRemediationPlan(buildRemediationPlan(report));
  const html = addPublicDisclosure(toHtml(report, { remediationPlan }), report.findings.length);
  return {
    report,
    html,
    retainedFindings: report.findings.length,
  };
}
