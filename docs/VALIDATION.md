# Validation

Last full local release gate: **2026-09-11 BRT**.

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
| npm test                    | 368 passed                                                                              |
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
| Node 24 / npm     | 260,547 B | 1,155,365 B      | 51,748,920 B           | 5.53 s  | 1.83 s |
| Node 24 / pnpm    | 260,547 B | 1,155,365 B      | 51,833,120 B           | 1.80 s  | 1.99 s |
| Node 24 / Yarn    | 260,547 B | 1,155,365 B      | 61,246,765 B           | 2.96 s  | 1.80 s |

The tarball contains 100 files. Next.js, React, SQLite, LangChain, LangGraph, and model-provider
packages are not installed for the CLI.

## Real-project calibration

These audits parsed captured source and manifests only. No target configuration module,
dependency installation, lifecycle script, test, build, or application code ran.

| Project                  | Snapshot                | Findings                             | Tasks | Coverage               | Important interpretation                                                    |
| ------------------------ | ----------------------- | ------------------------------------ | ----: | ---------------------- | --------------------------------------------------------------------------- |
| seusaas-platform         | 1,200 / 1,200, complete | 29: 2 high, 2 medium, 23 low, 2 info |    39 | 14 complete, 2 partial | Three web app roots; two informational crawler/sitemap candidates           |
| robs-web                 | 1,072 / 1,072, complete | 15: 11 medium, 1 low, 3 info         |    23 | 15 complete, 1 partial | Next.js root route group recognized as one app                              |
| capta-core               | 2,555 / 2,555, complete | 109: 15 high, 28 medium, 66 low      |   100 | 12 complete, 4 partial | Largest corpus member; remaining partial states are bounded mechanical data |
| aster-streaming-platform | 839 / 839, complete     | 3: 1 low, 2 info                     |     9 | 14 complete, 2 partial | Workspace build entrypoints map back to captured TypeScript source          |
| severyn                  | 314 / 314, complete     | 0                                    |     3 | 14 complete, 0 partial | Zero source candidates while missing runtime evidence remains explicit      |

For all five projects, imported Axe evidence was `NOT PERFORMED`, the authorized HTTP probe was
not run, and infrastructure/cloud behavior was not inferred. Optional external scanners and OSV
coverage depend on the selected local configuration. These runs prove portability, bounded
failure, and report honesty; they are not independent owner-confirmed security ground truth. The
anonymized calibration aggregate contains 156 candidates, zero reviewer labels, and correctly
reports `accuracyClaimReady: false`.

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
- CLI initialization, diagnostics, non-interactive behavior, package installation, and report server;
- persistent review UI, mobile/keyboard paths, mutation protections, and Chromium workflow.

## Release status

Version 0.2.1 is published on npm with a matching Git tag and public GitHub release. The current
source is the validated 0.3.0 candidate and has not been published or tagged. Ordinary pushes cannot
publish. Future releases still require the clean release gate, packed-artifact inspection, registry
verification, provenance, and a matching tag/release.

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
