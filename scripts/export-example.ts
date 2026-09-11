import path from 'node:path';
import os from 'node:os';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { format as formatDocument, resolveConfig as resolvePrettierConfig } from 'prettier';
import { captureSnapshot } from '../src/security/paths.ts';
import { scanPatterns } from '../src/scanners/builtin.ts';
import { scanPosture } from '../src/scanners/posture.ts';
import { profileProject } from '../src/scanners/project-profile.ts';
import { mergeFindings } from '../src/domain/findings.ts';
import { inventory } from '../src/scanners/inventory.ts';
import { toHtml, toMarkdown, toSarif } from '../src/domain/reports.ts';
import { buildCoverage } from '../src/domain/coverage.ts';
import { attachProvenance } from '../src/domain/provenance.ts';
import { buildSecurityChecklist } from '../src/domain/checklist.ts';
import { scanArchitecture, scanDuplication } from '../src/scanners/mechanical.ts';
import { scanSupplyChain } from '../src/scanners/supply-chain.ts';
import { scanCodeQuality } from '../src/scanners/quality.ts';
import type { AuditReport, ScannerRun } from '../src/domain/types.ts';

const source = await captureSnapshot(path.resolve('fixtures/review-worthy-saas'));
const supplyChainResult = scanSupplyChain(source);
const rawFindings = mergeFindings(
  mergeFindings(scanPatterns(source), scanPosture(source)),
  supplyChainResult.findings,
);
const profileResult = profileProject(source);
const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-example-'));
const [architectureResult, duplicationResult, qualityResult] = await Promise.all([
  scanArchitecture(source, profileResult.profile, temporary),
  scanDuplication(source, temporary),
  scanCodeQuality(source, profileResult.profile, temporary),
]).finally(() => rm(temporary, { recursive: true, force: true }));
const scanners: ScannerRun[] = [
  profileResult.run,
  {
    id: 'builtin',
    name: 'Built-in patterns',
    status: 'completed',
    durationMs: 0,
    findings: rawFindings.filter((finding) => finding.source === 'builtin').length,
    detail:
      'Seven bounded regex heuristics executed against inert fixtures. Duration not measured in this reproducible export.',
    version: '0.2.1',
  },
  {
    id: 'posture',
    name: 'Application posture',
    status: 'completed',
    durationMs: 0,
    findings: rawFindings.filter((finding) => finding.source === 'posture').length,
    detail: 'Conservative framework and configuration posture checks executed locally.',
    version: '0.2.1',
  },
  {
    id: 'semgrep',
    name: 'Semgrep',
    status: 'skipped',
    durationMs: 0,
    findings: 0,
    detail: 'Not executed for this fixture export.',
  },
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    status: 'skipped',
    durationMs: 0,
    findings: 0,
    detail: 'Not executed for this fixture export.',
  },
  {
    id: 'osv',
    name: 'Dependency vulnerabilities',
    status: 'skipped',
    durationMs: 0,
    findings: 0,
    detail: 'OSV lookup was disabled for this reproducible fixture export.',
  },
  { ...architectureResult.run, durationMs: 0 },
  { ...duplicationResult.run, durationMs: 0 },
  { ...supplyChainResult.run, durationMs: 0 },
  ...qualityResult.runs.map((run) => ({ ...run, durationMs: 0 })),
];
const findings = attachProvenance(rawFindings, scanners, '2026-09-08T12:00:00.000Z');
const dependencies = inventory(source);
const report: AuditReport = {
  schemaVersion: 5,
  auditId: '00000000-0000-4000-8000-000000000001',
  projectName: 'Review-worthy SaaS — fixture export',
  createdAt: '2026-09-08T12:00:00.000Z',
  snapshotDigest: source.digest,
  filesAnalyzed: source.files.length,
  skipped: source.skipped,
  truncated: source.truncated,
  aiMode: 'disabled',
  findings,
  scanners,
  dependencies,
  projectProfile: profileResult.profile,
  mechanicalAnalysis: {
    schemaVersion: 1,
    ...(architectureResult.analysis ? { architecture: architectureResult.analysis } : {}),
    ...(duplicationResult.analysis ? { duplication: duplicationResult.analysis } : {}),
  },
  supplyChainAnalysis: supplyChainResult.analysis,
  codeQualityAnalysis: qualityResult.analysis,
  checklist: buildSecurityChecklist({
    projectProfile: profileResult.profile,
    findings,
    scanners,
    dependencies,
  }),
  coverage: buildCoverage(scanners, findings, 'disabled'),
  limitations: [
    'This is an inert fixture export generated directly by the deterministic core, not an executed LangGraph audit.',
    'No model, optional external security scanner, or runtime exploit test was executed.',
    'Bundled dependency and duplication analysis ran against an isolated inert snapshot; its output is maintainability evidence, not a vulnerability verdict.',
    'All findings are review candidates; there are no automatically confirmed vulnerabilities.',
    'Regex heuristics can match comments and miss indirect flows. This is not a security certification.',
  ],
  publication: 'draft',
};
await mkdir('examples', { recursive: true });
const prettierConfig =
  (await resolvePrettierConfig(path.resolve('scripts/export-example.ts'))) ?? {};
for (const [extension, content] of [
  ['json', JSON.stringify(report, null, 2)],
  ['html', toHtml(report)],
  ['md', toMarkdown(report)],
  ['sarif', JSON.stringify(toSarif(report), null, 2)],
] as const) {
  const destination = `examples/fixture-review.${extension}`;
  await writeFile(
    destination,
    await formatDocument(content, { ...prettierConfig, filepath: destination }),
  );
}
console.log('Wrote deterministic fixture exports to examples/. No graph or model was executed.');
