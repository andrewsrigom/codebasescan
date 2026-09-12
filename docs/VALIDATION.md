# Validation

Last full local release gate: **2026-09-12 BRT**.

## Environment

- WSL2, Ubuntu 24.04.4 LTS
- Node.js 24.19.0 and npm 11.17.0
- Next.js 16.3.4
- Semgrep 1.176.1
- Gitleaks 8.30.1
- dependency-cruiser 18.2.0
- jscpd 5.2.0

Linux/WSL is the supported 0.3 candidate environment. Native Windows and macOS are not claimed.

## Release gate

| Check                       | Result                                                                                  |
| --------------------------- | --------------------------------------------------------------------------------------- |
| npm run release:metadata    | Passed; 0.3.0 candidate metadata valid and `private: false`                             |
| npm run format:check        | Passed                                                                                  |
| npm run typecheck           | Passed                                                                                  |
| npm run lint                | Passed, zero warnings                                                                   |
| npm test                    | 384 passed                                                                              |
| npm run benchmark           | TP 56, FP 0, FN 0; precision 1.00, recall 1.00                                          |
| AST benchmark subset        | TP 11, FP 0, FN 0; precision 1.00, recall 1.00                                          |
| Next.js benchmark subset    | TP 7, FP 0, FN 0; precision 1.00, recall 1.00                                           |
| React benchmark subset      | TP 9, FP 0, FN 0; precision 1.00, recall 1.00                                           |
| SaaS benchmark subset       | TP 9, FP 0, FN 0; precision 1.00, recall 1.00                                           |
| npm run test:integration    | 11 passed, including real scanners, deterministic fan-in, cache, and worker recovery    |
| npm run build               | Passed                                                                                  |
| npm run test:e2e            | 7 passed in Chromium                                                                    |
| npm audit --audit-level=low | 0 known vulnerabilities                                                                 |
| codebasescan doctor         | Runtime and bundled scanner checks passed; offline OSV cache absent warning is explicit |

The benchmark measures declared inert fixtures. It is not a generic accuracy claim or a security
certification.

## Packed installation

The actual tarball was installed into an empty generated project. Each smoke ran the installed
`doctor`, `init`, full static `audit`, current report package, and loopback report server.

| Runtime / manager | Tarball   | Unpacked package | Installed dependencies | Install | Audit  |
| ----------------- | --------- | ---------------- | ---------------------- | ------- | ------ |
| Node 24 / npm     | 268,998 B | 1,201,886 B      | 51,795,441 B           | 5.00 s  | 1.77 s |
| Node 24 / pnpm    | 268,998 B | 1,201,886 B      | 51,879,641 B           | 1.65 s  | 1.89 s |
| Node 24 / Yarn    | 268,998 B | 1,201,886 B      | 61,293,286 B           | 3.86 s  | 1.76 s |

The tarball contains 100 files. Next.js, React, SQLite, LangChain, LangGraph, and model-provider
packages are not installed for the CLI.

## Real-project calibration

These audits parsed captured source and manifests only. No target configuration module,
dependency installation, lifecycle script, test, build, or application code ran.

| Project | Snapshot complete | Findings                           | Candidate review | False-negative review | Core coverage          |
| ------- | ----------------- | ---------------------------------- | ---------------- | --------------------- | ---------------------- |
| P01     | 1,200 files       | 9: 1 high, 2 medium, 4 low, 2 info | 9 / 9 complete   | sampled               | 14 complete, 2 partial |
| P02     | 2,555 files       | 45: 6 high, 29 medium, 10 low      | 45 / 45 complete | sampled               | 12 complete, 4 partial |
| P03     | 415 files         | 0                                  | complete         | sampled               | 12 complete, 0 partial |
| P04     | 326 files         | 0                                  | complete         | not performed         | 14 complete, 0 partial |

The workflow-v54 aggregate contains 54 reviewer-labelled candidates: 39 true positives, 2 false
positives, and 13 not applicable. Sample precision is 95.1%; 53 of 54 evidence assessments were
correct, all 54 locations were correct, and 53 of 54 explanations were clear. The two remaining
false positives are documented broad generic-rule boundaries rather than silently removed.

The refreshed snapshots emitted all eight misses from the preceding bounded manual sample, so the
current ledgers record no outstanding miss. False-negative review is still incomplete for the
corpus, no recall is reported, and `accuracyClaimReady` remains false. Semgrep, Gitleaks, OSV, Axe,
and the HTTP probe were disabled or not performed in these four runs to isolate built-in source
rules. A separate trusted OSV refresh cached 805 exact package versions and passed `doctor`.

## What the gate covers

- bounded snapshot, path, symlink, size, and hostile-input protections;
- runtime/test/example scope separation;
- project profiling and code-first security rules;
- Node.js manifest and npm/pnpm/Yarn lockfile integrity checks;
- nine audit modes with explicit coverage and applicability;
- paired static accessibility and web-posture rules plus bounded Axe import;
- deterministic pipeline dependency validation, concurrent fan-in, focused modes, exact cache
  reuse, and worker recovery;
- Semgrep and Gitleaks isolated local adapters;
- dependency structure, duplication, dead code, complexity, and imported coverage summaries;
- OSV and HTTP boundaries with opt-in and bounded failure behavior;
- versioned agent report/rule schemas and the packaged Codex review skill installer;
- one current report package, stale-artifact cleanup, legacy-root reading, schemas, integrity
  manifest, comparison, and policy;
- reusable GitHub Action with full-context baseline comparison, HTML artifact upload, SARIF upload,
  and policy exit propagation;
- CLI initialization, diagnostics, non-interactive behavior, package installation, and report server;
- persistent review UI, mobile/keyboard paths, mutation protections, and Chromium workflow.

## Release status

Version 0.3.0 is published on npm with verified provenance, a matching Git tag, and a public GitHub
release. Its release gate passed locally and in GitHub Actions; clean registry installation reports
the exact version with no npm audit findings. Ordinary pushes cannot publish. Future releases still
require the clean release gate, packed-artifact inspection, registry verification, provenance, and
a matching tag/release.

Independent owner-confirmed ground truth, native platforms, signed reviewer/executor identity,
sharding beyond the 4,000-file / 32 MiB snapshot, and formal trademark clearance remain later
maturity work.

## Reproduce

```bash
npm ci
npm run release:check
npm run test:e2e
npm run test:package:pnpm
npm run test:package:yarn
```

External scanner integration tests require trusted Semgrep and Gitleaks binaries on `PATH`.
The audit has no built-in model provider. External coding agents use separately authorized,
versioned report and rule contracts.
