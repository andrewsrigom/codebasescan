# Validation record

## Scope and environment

Validation was performed during starter preparation on **2026-09-09 UTC (2026-09-08 BRT)**, using Linux and Node.js **22.16.0**. This is a factual record, not a release certification.

The container could not resolve the npm registry. A direct registry check returned:

```text
npm error code EAI_AGAIN
npm error syscall getaddrinfo
npm error request to https://registry.npmjs.org/next failed
```

Consequently, no third-party application dependencies were installed here and no real package lockfile was generated. There is no claim that the complete Next.js application or LangGraph integrations have passed build/runtime validation.

## Executed successfully

| Check | Result | What it establishes |
| --- | --- | --- |
| `npm test` | **47 passed, 0 failed, 0 skipped** | Dependency-free core tests on the selected Node runtime |
| `npm run benchmark` | Four expected fixture outcomes matched | Narrow heuristic regression harness, including one intentional false positive |
| Core TypeScript subset | Passed | Domain, scanner/security helpers, application store, core tests, and benchmark checked with globally available TypeScript |
| All-source syntax parse | 54 TypeScript/TSX files, no parse errors | Syntax only; not dependency-aware typechecking or a Next build |
| `npm run example` | Four report formats generated | Actual deterministic fixture scan and HTML/JSON/Markdown/SARIF generation, without a graph or model |
| Standalone HTML export in Chromium | Seven finding articles, zero scripts | Generated report layout inspected with actual browser rendering |
| Static JSX/CSS layout inspection | Desktop 1440px and mobile 390px; no horizontal page overflow | Styling-only rendering using a temporary local JSX serializer, not React hydration or Next.js |

The core typecheck used globally available **TypeScript 5.8.3 and Node type definitions 25.1.0**, not the declared project toolchain. A full check with the project's actual resolved dependencies remains mandatory. No validation helper or global compiler installation is bundled into the product.

Core coverage includes review candidate generation, benign fixtures, deliberate comment false positives, source path boundaries, symlinks, sensitive-file exclusion, size caps, redaction, scanner result validation, invalid line locations, secret match removal, report escaping, same-origin policy, body limits, SQLite queue/review state, idempotent events, worker lock, cancellation, and duplicate publication handling. Passing these tests is not proof of security completeness.

## Added but NOT executed here

| Check | Reason / next action |
| --- | --- |
| Project-wide `npm run typecheck` | Requires installed Next/React/LangGraph types and the project TypeScript version |
| `npm run lint` / Prettier | Requires declared development dependencies; source was syntax-formatted locally, not certified Prettier-clean |
| `npm run test:graph` | Requires the real LangGraph runtime and native SQLite checkpoint adapter |
| `npm run demo` through LangGraph | Requires the same graph dependencies; the included standalone example exports are a different, explicitly labeled core-only path |
| `npm run build` | Next.js/React were unavailable |
| `npm run test:e2e` | No installed Next.js application/runtime to start |
| Real Semgrep and Gitleaks invocations | Tool schemas/flags were checked against official docs; binaries were not present to execute |
| Real Ollama model inference | No model or Ollama server was installed |
| Crash-injection and abrupt process termination | Needs full graph/worker runtime validation, including staging cleanup behavior |
| Native Windows/macOS | Not available in this Linux environment |

## Release gate

Follow `CODEX_HANDOFF.md` P0. Resolve dependencies, generate and commit a real lockfile, run all actual checks, inspect the real UI, and record exact package/scanner/model versions. Keep this warning visible until those checks pass. Do not infer full integration correctness from the 47 core tests or from a static styling screenshot.
