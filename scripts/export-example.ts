import path from 'node:path';
import { mkdir, writeFile } from 'node:fs/promises';
import { captureSnapshot } from '../src/security/paths.ts';
import { scanPatterns } from '../src/scanners/builtin.ts';
import { mergeFindings } from '../src/domain/findings.ts';
import { inventory } from '../src/scanners/inventory.ts';
import { toHtml, toMarkdown, toSarif } from '../src/domain/reports.ts';
import type { AuditReport } from '../src/domain/types.ts';

const source = await captureSnapshot(path.resolve('fixtures/review-worthy-saas'));
const findings = mergeFindings([], scanPatterns(source));
const report: AuditReport = {
  schemaVersion: 1,
  auditId: '00000000-0000-4000-8000-000000000001',
  projectName: 'Review-worthy SaaS — fixture export',
  createdAt: '2026-09-08T12:00:00.000Z',
  snapshotDigest: source.digest,
  filesAnalyzed: source.files.length,
  skipped: source.skipped,
  truncated: source.truncated,
  aiMode: 'disabled',
  findings,
  scanners: [
    { id: 'builtin', name: 'Built-in patterns', status: 'completed', durationMs: 0, findings: findings.length, detail: 'Seven regex heuristics executed against inert fixtures. Duration not measured in this reproducible export.' },
    { id: 'semgrep', name: 'Semgrep', status: 'skipped', durationMs: 0, findings: 0, detail: 'Not executed for this fixture export.' },
    { id: 'gitleaks', name: 'Gitleaks', status: 'skipped', durationMs: 0, findings: 0, detail: 'Not executed for this fixture export.' },
    { id: 'dependency-matching', name: 'Dependency vulnerabilities', status: 'skipped', durationMs: 0, findings: 0, detail: 'Manifest inventory only; vulnerability matching is not implemented.' },
  ],
  dependencies: inventory(source),
  limitations: [
    'This is an inert fixture export generated directly by the deterministic core, not an executed LangGraph audit.',
    'No model, external scanner, or runtime exploit test was executed.',
    'All findings are review candidates; there are no automatically confirmed vulnerabilities.',
    'Regex heuristics can match comments and miss indirect flows. This is not a security certification.',
  ],
  publication: 'draft',
};
await mkdir('examples', { recursive: true });
for (const [extension, content] of [
  ['json', JSON.stringify(report, null, 2)],
  ['html', toHtml(report)],
  ['md', toMarkdown(report)],
  ['sarif', JSON.stringify(toSarif(report), null, 2)],
] as const) {
  await writeFile(`examples/fixture-review.${extension}`, content + '\n');
}
console.log('Wrote deterministic fixture exports to examples/. No graph or model was executed.');
