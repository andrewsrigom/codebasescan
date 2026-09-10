# Validation

Last full local gate: **2026-09-09 BRT**.

Environment:

- WSL2, Ubuntu 24.04.4 LTS
- Node.js 24.19.0, npm 11.17.0
- Next.js 16.3.4
- Semgrep 1.176.1
- Gitleaks 8.30.1
- dependency-cruiser 18.2.0
- jscpd 5.2.0

## Current results

| Check                         | Result                                                                 |
| ----------------------------- | ---------------------------------------------------------------------- |
| npm run format:check          | Passed                                                                 |
| npm run typecheck             | Passed                                                                 |
| npm run lint                  | Passed, zero warnings                                                  |
| npm test                      | 214 passed                                                             |
| npm run test:graph            | 11 passed, including real scanners and worker recovery                 |
| npm run benchmark             | TP 36, FP 1, FN 0; precision 0.9730, recall 1.00                       |
| AST benchmark subset          | TP 11, FP 0, FN 0; precision 1.00, recall 1.00                         |
| Next.js benchmark subset      | TP 7, FP 0, FN 0; precision 1.00, recall 1.00                          |
| React benchmark subset        | TP 9, FP 0, FN 0; precision 1.00, recall 1.00                          |
| npm run build                 | Passed                                                                 |
| npm run test:e2e              | 7 passed in Chromium                                                   |
| npm audit --audit-level=low   | 0 known vulnerabilities                                                |
| npm run cli -- doctor         | 9 checks passed                                                        |
| Browser workspace             | Dependency plans rendered real data with no overlay or console error   |
| Standalone HTML report        | Decision summary, priority links, mobile width 390/390, no script tags |
| Ten-project source evaluation | 10 profiles, 1,010 files, 0 truncations, 23 final candidates           |
| Owner-authorized scale pass   | 2 profiles, 2,235 files, 0 truncations, 6.62–9.82 s, 448–574 MiB peak  |
| Latest `seusaas` offline run  | 1,196 files, 0 snapshot truncations, 112 candidates, 7 checklist gaps  |

The latest full offline `seusaas-platform` run included Semgrep, Gitleaks, OSV,
dependency-cruiser, jscpd, Knip, supply-chain checks, TypeScript quality metrics,
the project profile, and the built-in AST/Next.js/React rules. It captured 1,196 files and
mapped 739 runtime modules, 295 local dependencies, one cycle, 50 orphan candidates, and 188
coupling hotspots (100 detail rows retained). It measured 6,064 functions and found 259 quality
hotspots (200 retained), 54 duplicate blocks (2.7026%), 55 unused-file candidates, 6
source-unreferenced runtime dependencies, 149 unused exports, 78 unused types, and 21 unlisted
dependency candidates. The profile completed with 3,424 imports. Semgrep produced no finding and
reported one explicit partial parse at
`apps/analytics/src/features/reports/reports-preview.tsx:87`; all other omitted detail is reported
with exact totals. The checklist retained 8 evidenced controls, 7 gap candidates, 7 unverified
controls, and one partial control. The 112 security candidates were 4 critical, 63 high, 37 medium,
and 8 low: 101 exact-version OSV advisories across 26 affected packages plus 11 source candidates.
The corrected pnpm inventory retained 1,094 distinct dependencies, including full scoped-package
names; remediation plans were verified in the workspace, Markdown, HTML, and Codex bundle. Calibration against this run
removed 45 reproducible false positives without weakening the declared benchmark. No target code,
configuration module, test, or package lifecycle script ran.

The benchmark measures declared inert fixtures. It is not a generic accuracy claim. The public-project pass has manual triage but not owner-confirmed ground truth; see [Real-project evaluation](REAL_PROJECT_EVALUATION.md).

## What the gate covers

- bounded snapshot and path protections;
- runtime/test/example scope separation;
- project profiling and code-first security rules;
- Node.js manifest and npm/pnpm/Yarn lockfile integrity checks;
- explicit coverage, checklist, provenance, and report validation;
- LangGraph interrupt/resume and SQLite persistence;
- Semgrep and Gitleaks local adapters;
- bounded dependency structure and duplication reports without loading target configuration;
- isolated Knip candidates, source-only runtime dependency references, complexity, size, and
  existing coverage summaries;
- OSV, HTTP, and OpenAI contracts with bounded failure behavior;
- human finding/control review, publication, exports, comparison, and CI gates;
- desktop/mobile navigation and the main review flow.

OpenAI uses mocked Responses API contracts because no API key was supplied. Ollama is optional and was not installed.

## Remaining release work

- independent owner-confirmed review, including manually found false negatives and durable dispositions;
- live economical/strong OpenAI and local Ollama comparison only with explicit cost approval;
- fresh comprehensive accessibility audit;
- clean-clone and any claimed native Windows/macOS support checks;
- private vulnerability-reporting route and name/trademark review before publishing;
- broader scanner-version and abrupt-failure compatibility matrix.

These gaps do not block the validated local WSL2 workflow. They do block broader platform, model-quality, accuracy, or public-production claims.

## Reproduce

```bash
npm ci
npm run format:check
npm run typecheck
npm run lint
npm test
npm run test:graph
npm run benchmark
npm run build
npm run test:e2e
npm audit --audit-level=low
```

External security scanner tests require the trusted Semgrep and Gitleaks binaries on PATH.
dependency-cruiser, jscpd, and Knip are pinned project dependencies. Default AI mode remains
disabled.
