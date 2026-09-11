# Validation

Last full local release gate: **2026-09-10 BRT**.

## Environment

- WSL2, Ubuntu 24.04.4 LTS
- Node.js 24.19.0 and npm 11.17.0
- additional installed-package smoke: Node.js 22.22.1
- Next.js 16.3.4
- Semgrep 1.176.1
- Gitleaks 8.30.1
- dependency-cruiser 18.2.0
- jscpd 5.2.0

Linux/WSL is the supported 0.2 environment. Native Windows and macOS are not claimed.

## Release gate

| Check                       | Result                                                                                  |
| --------------------------- | --------------------------------------------------------------------------------------- |
| npm run release:metadata    | Passed; 0.2.0 metadata valid and `private: true` still blocks publish                   |
| npm run format:check        | Passed                                                                                  |
| npm run typecheck           | Passed                                                                                  |
| npm run lint                | Passed, zero warnings                                                                   |
| npm test                    | 340 passed                                                                              |
| npm run benchmark           | TP 55, FP 1, FN 0; precision 0.9821, recall 1.00                                        |
| AST benchmark subset        | TP 11, FP 0, FN 0; precision 1.00, recall 1.00                                          |
| Next.js benchmark subset    | TP 7, FP 0, FN 0; precision 1.00, recall 1.00                                           |
| React benchmark subset      | TP 9, FP 0, FN 0; precision 1.00, recall 1.00                                           |
| SaaS benchmark subset       | TP 9, FP 0, FN 0; precision 1.00, recall 1.00                                           |
| npm run test:graph          | 13 passed, including real scanners, cache, and worker recovery                          |
| npm run build               | Passed                                                                                  |
| npm run test:e2e            | 7 passed in Chromium                                                                    |
| npm audit --audit-level=low | 0 known vulnerabilities                                                                 |
| codebasescan doctor         | Runtime and bundled scanner checks passed; offline OSV cache absent warning is explicit |

The benchmark measures declared inert fixtures. It is not a generic accuracy claim or a security
certification.

## Packed installation

The actual tarball was installed into an empty generated project. Each smoke ran the installed
`doctor`, `init`, full static `audit`, stable report history, and loopback report server.

| Runtime / manager | Tarball   | Unpacked package | Installed dependencies | Install | Audit  |
| ----------------- | --------- | ---------------- | ---------------------- | ------- | ------ |
| Node 24 / npm     | 245,508 B | 1,099,828 B      | 95,396,481 B           | 6.05 s  | 2.78 s |
| Node 22 / npm     | 245,508 B | 1,099,828 B      | 95,396,358 B           | 4.86 s  | 3.17 s |
| Node 24 / pnpm    | 245,508 B | 1,099,828 B      | 95,481,763 B           | 6.86 s  | 2.93 s |
| Node 24 / Yarn    | 245,508 B | 1,099,828 B      | 104,887,481 B          | 10.02 s | 2.61 s |

The tarball contains 90 files. Next.js, React, shadcn, SQLite checkpoint, and Ollama packages are
not installed for the default CLI. Node 22 one-shot commands do not load `node:sqlite` or emit its
experimental warning.

## Real-project calibration

These audits parsed captured source and manifests only. No target configuration module,
dependency installation, lifecycle script, test, build, or application code ran.

| Project           | Snapshot                                                    | Findings                             | Tasks                | Coverage               | Important interpretation                                                 |
| ----------------- | ----------------------------------------------------------- | ------------------------------------ | -------------------- | ---------------------- | ------------------------------------------------------------------------ |
| seusaas-platform  | 1,201 / 1,201, complete                                     | 29: 2 high, 2 medium, 23 low, 2 info | 39                   | 14 complete, 2 partial | Three web app roots; two informational crawler/sitemap candidates        |
| robs-web          | 1,074 / 1,074, complete                                     | 15: 11 medium, 1 low, 3 info         | 23                   | 15 complete, 1 partial | Next.js root route group recognized as one app                           |
| capta-core        | 1,500 / 2,580, truncated by file/per-file/total-byte limits | 164: 17 high, 116 medium, 31 low     | 159                  | 16 partial             | Owner triage is required; counts cannot support a complete verdict       |
| fengsoft-commerce | 425 / 425, complete                                         | 0                                    | 6 verification tasks | 12 complete            | No React/Next web root detected; zero is not a clean full-stack verdict  |
| severyn           | 307 / 307 supported files, complete                         | 2 info                               | 5 verification tasks | 15 complete            | Primarily outside the JS/TS focus, with one detected React web component |

For all five projects, imported Axe evidence was `NOT PERFORMED`, the authorized HTTP probe was
not run, and infrastructure/cloud behavior was not inferred. Optional external scanners and OSV
coverage depend on the selected local configuration. These runs prove portability, bounded
failure, and report honesty; they are not independent owner-confirmed security ground truth.

## What the gate covers

- bounded snapshot, path, symlink, size, and hostile-input protections;
- runtime/test/example scope separation;
- project profiling and code-first security rules;
- Node.js manifest and npm/pnpm/Yarn lockfile integrity checks;
- nine audit modes with explicit coverage and applicability;
- paired static accessibility and web-posture rules plus bounded Axe import;
- LangGraph fan-in, interrupt/resume, memory and SQLite checkpoints;
- Semgrep and Gitleaks isolated local adapters;
- dependency structure, duplication, dead code, complexity, and imported coverage summaries;
- OSV, HTTP, Ollama, and OpenAI boundaries with opt-in and bounded failure behavior;
- immutable report packages, stable history, schemas, integrity manifest, comparison, and policy;
- CLI initialization, diagnostics, non-interactive behavior, package installation, and report server;
- persistent review UI, mobile/keyboard paths, mutation protections, and Chromium workflow.

## Remaining publication actions

- push the current release candidate and require the public GitHub matrix to pass;
- confirm the npm name immediately before publication and secure the npm account with 2FA;
- inspect the final tarball and generated report for private data;
- configure the protected npm OIDC publisher;
- remove `private: true` only in the explicit release commit;
- push the matching version tag, verify npm provenance/fresh install, then create the GitHub release.

Independent owner-confirmed ground truth, native platforms, signed reviewer/executor identity,
large-project sharding, and formal trademark clearance remain later maturity work.

## Reproduce

```bash
npm ci
npm run release:check
npm run test:e2e
npm run test:package:pnpm
npm run test:package:yarn
```

External scanner integration tests require trusted Semgrep and Gitleaks binaries on `PATH`.
Default AI mode remains disabled.
