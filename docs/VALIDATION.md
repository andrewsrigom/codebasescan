# Validation record

## Code-first audit pass

Validation was repeated on **2026-09-09 BRT** in WSL2 Ubuntu **24.04.4 LTS**, Node.js **24.19.0**, npm **11.17.0**, Next.js **16.3.4**, Semgrep **1.176.1**, and Gitleaks **8.30.1**.

| Check                         | Result                                                                                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `npm run format:check`        | Passed                                                                                                                                    |
| `npm run typecheck`           | Passed                                                                                                                                    |
| `npm run lint`                | Passed with zero warnings                                                                                                                 |
| `npm test`                    | **134 passed**, 0 failed, 0 skipped                                                                                                       |
| `npm run test:graph`          | **8 passed**, including real scanners, actual worker `SIGKILL`, checkpoint/config rejection, and disabled-network behavior                |
| Interrupt/resume repetition   | **50 consecutive passes** using exact persisted checkpoint and interrupt IDs                                                              |
| Worker crash recovery         | A replacement worker recovered persisted state after actual `SIGKILL`; cleanup remains limited to recognized staging names                |
| `npm run benchmark`           | TP 19, FP 1, FN 0, precision 0.95, recall 1.00; AST subset TP 10, FP 0, FN 0, precision 1.00, recall 1.00                                 |
| `npm run build`               | Passed; all application and API routes compiled                                                                                           |
| `npm run test:e2e`            | **6 passed** in Chromium, including scope preflight and persisted human checklist assessment                                              |
| `npm audit --audit-level=low` | 0 known vulnerabilities                                                                                                                   |
| Browser verification          | Fresh audit rendered Project Map, 17 checklist controls, source-scope preflight and bounded-investigation state; no framework error UI    |
| Browser console               | No page errors; only expected Next.js development messages                                                                                |
| Local HTTP response           | HTTP 200 with CSP, frame, MIME, referrer, permissions and cache-control headers                                                           |
| Traceward self-audit          | 185 supported files: 76 runtime, 108 test, 1 example; complete profile/scanners and one low HSTS declaration candidate                    |
| Dependency hardening          | Bounded OSV pagination, package-level CVSS v3 severity, cache compatibility, and npm/Yarn local-workspace exclusion covered               |
| CI/compatibility              | Baseline-only gates, JSON/SARIF artifacts, scope approval, scanner-version warnings, and workflow/config fingerprints covered             |
| Checklist review              | Human external-evidence/gap/follow-up decisions append revisions, keep deterministic status, survive publication, and export              |
| Real-project source pass      | 10 public repositories, 1,010 supported files, 10 complete profiles, 0 truncations, 23 final candidates; see `REAL_PROJECT_EVALUATION.md` |

The benchmark uses declared fixtures and is not a general accuracy claim. The self-audit is one authorized repository, not a diverse evaluation set. Its first pass exposed fixture/benchmark findings being treated as application code; runtime/test/example separation removed those two noise candidates while Gitleaks retained all captured scopes. The remaining low header candidate identifies absent static HSTS evidence without claiming the loopback-only runtime is vulnerable.

Deterministic profiling, ten AST rules, checklist mapping, evidence-ID context brokerage, bounded investigation output, persisted schema validation, report revisions, Codex bundle export, and anonymized outcome aggregation are covered without enabling a model provider.

OpenAI remains covered by mocked contract tests only because no credential was supplied. Ollama remains optional and uninstalled. The ten-project pass demonstrates real-project behavior but does not provide owner-confirmed ground truth or justify a general accuracy claim. Private-project evaluation still requires explicit source and retention approval.

## Security workflow expansion pass

Validation was repeated on **2026-09-09 BRT** in WSL2 Ubuntu **24.04.4 LTS**, Node.js **24.19.0**, npm **11.17.0**, Next.js **16.3.4**, Semgrep **1.176.1**, and Gitleaks **8.30.1**.

| Check                         | Result                                                                                                   |
| ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| `npm run format:check`        | Passed                                                                                                   |
| `npm run typecheck`           | Passed                                                                                                   |
| `npm run lint`                | Passed with zero warnings                                                                                |
| `npm test`                    | **72 passed**, 0 failed, 0 skipped                                                                       |
| `npm run test:graph`          | **6 passed**, including real Semgrep/Gitleaks adapter execution                                          |
| `npm run benchmark`           | TP 9, FP 1, FN 0, precision 0.90, recall 1.00                                                            |
| `npm run build`               | Passed; all application and API routes compiled                                                          |
| `npm run test:e2e`            | **4 passed** in Chromium                                                                                 |
| `npm audit --audit-level=low` | 0 known vulnerabilities                                                                                  |
| Browser verification          | Meaningful UI content, coverage and HTTP-audit controls present, settings rendered, no framework overlay |
| Live HTTP posture probe       | HEAD 200 against the local app; five selected security headers observed; zero probe findings             |
| Live OSV lookup               | Completed for lodash 4.17.20; three consolidated advisory groups with aliases and fixed versions         |
| CI severity gates             | Clean fixture exited 0; review-worthy fixture exited 1; JSON and SARIF output exercised                  |

OpenAI Responses API behavior is covered by mocked contract tests for structured output, `store=false`, redaction, prompt-injection boundaries, retries, timeout, caching, usage, cost metadata, and hard budgets. A live OpenAI call was not performed because no API key was available. Ollama remains uninstalled and unvalidated. These are visible coverage gaps, not clean results.

The expanded workflow still does not establish scanner completeness, dependency reachability, exploitability, compliance, or security certification. WSL2/Linux remains the validated platform.

## Runnable stabilization pass

Validation was performed on **2026-09-09 UTC (2026-09-08 BRT)** in WSL2, using Ubuntu **24.04.4 LTS**, Linux **6.18.33.2-microsoft-standard-WSL2**, Node.js **24.19.0**, and npm **11.17.0**. The default local mode kept AI, Semgrep, and Gitleaks disabled.

`npm install` generated a real lockfile and resolved the principal runtime packages to Next.js **16.3.4**, React/React DOM **19.2.8**, LangGraph **1.4.14**, LangGraph checkpoint **1.1.5**, LangGraph SQLite checkpoint **1.0.4**, LangChain core **1.2.9**, LangChain Ollama **1.3.0**, `better-sqlite3` **12.11.1**, Zod **4.5.4**, TypeScript **5.9.3**, and Playwright **1.63.0**. Chromium testing used Chrome for Testing **153.0.8010.12**. `npm ls` reported one compatible copy of each principal dependency.

### Executed successfully in this pass

| Check                         | Result                                                                           | What it establishes                                                                                                               |
| ----------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `npm install`                 | 408 packages installed; real `package-lock.json` generated                       | The selected dependency and native SQLite graph can be resolved in the primary WSL environment                                    |
| `npm run format:check`        | Passed                                                                           | Tracked source and documentation, excluding generated `next-env.d.ts`, match Prettier                                             |
| `npm run typecheck`           | Passed                                                                           | Full application, graph, routes, worker, scripts, and tests compile against the resolved dependencies                             |
| `npm run lint`                | Passed with zero warnings                                                        | ESLint accepts the complete project                                                                                               |
| `npm test`                    | 48 passed, 0 failed, 0 skipped                                                   | Core domain, storage, scanner normalization, snapshot, HTTP, report escaping, and cancellation behavior                           |
| `npm run benchmark`           | Four expected fixture outcomes matched                                           | Narrow heuristic regression harness, including the intentional comment false positive                                             |
| `npm run test:graph`          | 3 passed, 0 failed, 0 skipped                                                    | Real LangGraph fan-in, bounded subgraph loop, interrupt/resume, and SQLite checkpoint reconstruction                              |
| `npm run build`               | Passed with no Turbopack warnings                                                | Next.js production compilation, TypeScript, page-data collection, and route generation                                            |
| `npm run test:e2e`            | 4 passed in Chromium                                                             | Evidence display, coverage gaps, HTML download, cross-origin rejection, mobile navigation names, and keyboard tab behavior        |
| Manual browser flow           | Passed                                                                           | CLI registration → UI queue → separate worker → `awaiting_review` → finding review persistence → publication resume → `completed` |
| Browser console/network       | No page errors or framework overlay; all observed requests stayed on `127.0.0.1` | The exercised default UI did not make unexpected outbound requests                                                                |
| Desktop/mobile layout         | 1440px and 390px inspected; mobile document width equaled viewport width         | Meaningful rendering without page-level horizontal overflow                                                                       |
| Production start              | `npm run start` returned HTTP 200                                                | The built server starts on loopback and emits CSP, frame, MIME, referrer, permissions, and no-store headers                       |
| HTTP negative checks          | Host and cross-origin requests returned 403; malformed JSON returned 400         | Runtime request guards reject the exercised invalid inputs                                                                        |
| `npm audit --audit-level=low` | 0 known vulnerabilities                                                          | npm reported no advisory matches in the resolved dependency tree at validation time                                               |
| Real Semgrep invocation       | Semgrep 1.176.1 completed; two expected findings on the review-worthy fixture    | The installed CLI, trusted local rules, JSON output, and positive detection path execute in WSL2                                  |
| Real Gitleaks invocation      | Gitleaks 8.30.1 completed; release archive checksum verified                     | The installed CLI, trusted default rules, redacted JSON report path, and clean-result path execute in WSL2                        |
| External-scanner worker flow  | Both scanners reported `completed` on the hardened fixture                       | The worker staging, subprocess limits, JSON normalization, cleanup, persistence, and coverage reporting execute end to end        |

The initial mobile axe run found missing accessible names on the collapsed navigation and widespread low-contrast small text. The accessible-name/ARIA defects were corrected, the reported contrast set was reduced from 75 nodes to seven, and those seven remaining foreground colors were darkened. The final browser regression covers the navigation names and keyboard tabs; a fresh comprehensive axe pass remains advisable before a public portfolio release.

### Remaining release gaps

- Semgrep 1.176.1 and Gitleaks 8.30.1 are installed and their successful real-binary paths have been validated in this WSL environment. Broader nonzero exit states, malformed real output, timeouts, and version-upgrade compatibility still need a scanner compatibility matrix.
- Ollama is not installed in this WSL environment. The local-model adapter is covered by schema and failure contracts, but real model output, latency, resource use, and timeout behavior have not been validated.
- Abrupt process termination, raw staging cleanup after `SIGKILL`/power loss, and broader restart/cancellation fault injection remain pending.
- Native Windows and macOS execution have not been tested. WSL2/Linux remains the primary validated target.
- The npm install reported deprecation notices for the resolved ESLint 9 line and `prebuild-install`; the tested major versions were retained because upgrading `better-sqlite3`, TypeScript, and ESLint requires a separate compatibility pass.
- This pass does not establish scanner completeness, exploitability, compliance, or security certification.

## Earlier starter-preparation record

### Scope and environment

Validation was performed during starter preparation on **2026-09-09 UTC (2026-09-08 BRT)**, using Linux and Node.js **22.16.0**. This is a factual record, not a release certification.

The container could not resolve the npm registry. A direct registry check returned:

```text
npm error code EAI_AGAIN
npm error syscall getaddrinfo
npm error request to https://registry.npmjs.org/next failed
```

Consequently, no third-party application dependencies were installed here and no real package lockfile was generated. There is no claim that the complete Next.js application or LangGraph integrations have passed build/runtime validation.

### Executed successfully

| Check                              | Result                                                       | What it establishes                                                                                                       |
| ---------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `npm test`                         | **47 passed, 0 failed, 0 skipped**                           | Dependency-free core tests on the selected Node runtime                                                                   |
| `npm run benchmark`                | Four expected fixture outcomes matched                       | Narrow heuristic regression harness, including one intentional false positive                                             |
| Core TypeScript subset             | Passed                                                       | Domain, scanner/security helpers, application store, core tests, and benchmark checked with globally available TypeScript |
| All-source syntax parse            | 54 TypeScript/TSX files, no parse errors                     | Syntax only; not dependency-aware typechecking or a Next build                                                            |
| `npm run example`                  | Four report formats generated                                | Actual deterministic fixture scan and HTML/JSON/Markdown/SARIF generation, without a graph or model                       |
| Standalone HTML export in Chromium | Seven finding articles, zero scripts                         | Generated report layout inspected with actual browser rendering                                                           |
| Static JSX/CSS layout inspection   | Desktop 1440px and mobile 390px; no horizontal page overflow | Styling-only rendering using a temporary local JSX serializer, not React hydration or Next.js                             |

The core typecheck used globally available **TypeScript 5.8.3 and Node type definitions 25.1.0**, not the declared project toolchain. A full check with the project's actual resolved dependencies remains mandatory. No validation helper or global compiler installation is bundled into the product.

Core coverage includes review candidate generation, benign fixtures, deliberate comment false positives, source path boundaries, symlinks, sensitive-file exclusion, size caps, redaction, scanner result validation, invalid line locations, secret match removal, report escaping, same-origin policy, body limits, SQLite queue/review state, idempotent events, worker lock, cancellation, and duplicate publication handling. Passing these tests is not proof of security completeness.

### Added but NOT executed there

| Check                                          | Reason / next action                                                                                                             |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Project-wide `npm run typecheck`               | Requires installed Next/React/LangGraph types and the project TypeScript version                                                 |
| `npm run lint` / Prettier                      | Requires declared development dependencies; source was syntax-formatted locally, not certified Prettier-clean                    |
| `npm run test:graph`                           | Requires the real LangGraph runtime and native SQLite checkpoint adapter                                                         |
| `npm run demo` through LangGraph               | Requires the same graph dependencies; the included standalone example exports are a different, explicitly labeled core-only path |
| `npm run build`                                | Next.js/React were unavailable                                                                                                   |
| `npm run test:e2e`                             | No installed Next.js application/runtime to start                                                                                |
| Real Semgrep and Gitleaks invocations          | Tool schemas/flags were checked against official docs; binaries were not present to execute                                      |
| Real Ollama model inference                    | No model or Ollama server was installed                                                                                          |
| Crash-injection and abrupt process termination | Needs full graph/worker runtime validation, including staging cleanup behavior                                                   |
| Native Windows/macOS                           | Not available in this Linux environment                                                                                          |

### Release gate at that time

Follow `CODEX_HANDOFF.md` P0. Resolve dependencies, generate and commit a real lockfile, run all actual checks, inspect the real UI, and record exact package/scanner/model versions. Keep this warning visible until those checks pass. Do not infer full integration correctness from the 47 core tests or from a static styling screenshot.
