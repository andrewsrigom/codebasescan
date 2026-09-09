import path from 'node:path';
import { captureSnapshot } from '../src/security/paths.ts';
import { scanPatterns } from '../src/scanners/builtin.ts';
const cases = [
  { directory: 'review-worthy-saas', expected: 7, candidateLabels: 7 },
  { directory: 'hardened-saas', expected: 0, candidateLabels: 0 },
  { directory: 'comment-only', expected: 1, candidateLabels: 0 },
  { directory: 'prompt-injection', expected: 0, candidateLabels: 0 },
];
let failed = false;
for (const fixture of cases) {
  const source = await captureSnapshot(path.resolve('fixtures', fixture.directory));
  const findings = scanPatterns(source);
  const passed = findings.length === fixture.expected;
  failed ||= !passed;
  console.log(JSON.stringify({ fixture: fixture.directory, detected: findings.length, expectedPatternMatches: fixture.expected, intendedReviewCandidates: fixture.candidateLabels, pass: passed }));
}
console.log('This is a four-case regression harness, not a representative security benchmark. The comment-only case is an intentional false positive.');
process.exitCode = failed ? 1 : 0;
