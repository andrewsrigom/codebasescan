# Validation

Last full local gate: **2026-09-09 BRT**.

Environment:

- WSL2, Ubuntu 24.04.4 LTS
- Node.js 24.19.0, npm 11.17.0
- Next.js 16.3.4
- Semgrep 1.176.1
- Gitleaks 8.30.1

## Current results

| Check                         | Result                                                                 |
| ----------------------------- | ---------------------------------------------------------------------- |
| npm run format:check          | Passed                                                                 |
| npm run typecheck             | Passed                                                                 |
| npm run lint                  | Passed, zero warnings                                                  |
| npm test                      | 166 passed                                                             |
| npm run test:graph            | 9 passed, including real scanners and worker recovery                  |
| npm run benchmark             | TP 35, FP 1, FN 0; precision 0.9722, recall 1.00                       |
| AST benchmark subset          | TP 10, FP 0, FN 0; precision 1.00, recall 1.00                         |
| Next.js benchmark subset      | TP 7, FP 0, FN 0; precision 1.00, recall 1.00                          |
| React benchmark subset        | TP 9, FP 0, FN 0; precision 1.00, recall 1.00                          |
| npm run build                 | Passed                                                                 |
| npm run test:e2e              | 6 passed in Chromium                                                   |
| npm audit --audit-level=low   | 0 known vulnerabilities                                                |
| Browser workspace             | Meaningful content, no framework overlay, responsive width, no errors  |
| Standalone HTML report        | Decision summary, priority links, mobile width 390/390, no script tags |
| Ten-project source evaluation | 10 profiles, 1,010 files, 0 truncations, 23 final candidates           |

The benchmark measures declared inert fixtures. It is not a generic accuracy claim. The public-project pass has manual triage but not owner-confirmed ground truth; see [Real-project evaluation](REAL_PROJECT_EVALUATION.md).

## What the gate covers

- bounded snapshot and path protections;
- runtime/test/example scope separation;
- project profiling and code-first security rules;
- explicit coverage, checklist, provenance, and report validation;
- LangGraph interrupt/resume and SQLite persistence;
- Semgrep and Gitleaks local adapters;
- OSV, HTTP, and OpenAI contracts with bounded failure behavior;
- human finding/control review, publication, exports, comparison, and CI gates;
- desktop/mobile navigation and the main review flow.

OpenAI uses mocked Responses API contracts because no API key was supplied. Ollama is optional and was not installed.

## Remaining release work

- independent review on owner-authorized applications, including manually found false negatives;
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

External scanner tests require the trusted Semgrep and Gitleaks binaries on PATH. Default AI mode remains disabled.
