# Real-project evaluation

## 2026-09-09 source-only pass

CodebaseScan was run locally against ten public TypeScript/Next.js repositories selected to cover App Router, Pages Router, monorepo layouts, authentication wrappers, Prisma-style data access, middleware, uploads, and third-party integrations. Projects are labeled A-J because this document evaluates CodebaseScan, not the upstream projects.

No target dependency was installed, no target script was run, and no target module was imported. AI, OSV network lookup, and the HTTP probe were disabled for this pass. The installed Semgrep 1.176.1 and Gitleaks 8.30.1 adapters were enabled. Repository copies and raw reports remained temporary and are not committed.

| Measure                             |         Result |
| ----------------------------------- | -------------: |
| Projects                            |             10 |
| Supported files captured            |          1,010 |
| Smallest / largest snapshot         | 26 / 310 files |
| Complete structural profiles        |             10 |
| Truncated final snapshots           |              0 |
| Core deterministic scanner failures |              0 |
| Final review candidates             |             23 |
| High / medium / low                 |      5 / 9 / 9 |

Manual triage grouped the final candidates as follows. These labels are evaluator judgments, not owner-confirmed vulnerabilities:

- 3 strong source-backed code risks: two database-mutating inline server actions without a mapped authentication guard and one request-stream upload without mapped size, type, or path constraints;
- 2 secret-shaped values used in test/development configuration, correctly withheld by the report but requiring context rather than an automatic credential claim;
- 9 medium review hotspots: six ID-only object lookups, two raw HTML sinks, and one read-only server action without a mapped session;
- 9 low static header gaps that require deployment or runtime evidence before disposition.

No general precision or recall is reported for this dataset. The pass did not include exhaustive independent manual review, owner dispositions, runtime behavior, deployment configuration, dependency advisories, or a known-vulnerability ground truth.

## Changes driven by the pass

The first passes exposed real failure modes and directly produced regression tests:

- standard npm/pnpm lockfiles larger than the generic source-file cap caused three partial snapshots; lockfiles now have a separate bounded 4 MiB allowance;
- inline `"use server"` functions were missing from the entrypoint map;
- wrapped, aliased, destructured, and Pages Router handlers were incompletely mapped;
- common captured `@/`, `~/`, and root aliases did not participate in the bounded call map;
- direct request-body uploads were not recognized;
- response serialization in webhook-management APIs was mistaken for request-body parsing;
- `process.env.NODE_ENV`, same-origin URL bases, configured origin replacement, trusted client responses, strict host-label allowlisting, and file-validation schemas created avoidable AST noise;
- generic ID-only lookups and read-only server actions carried severity that was too strong for their evidence.

Across the same ten repositories, the initial 32-candidate set lost 12 reviewed AST false positives and gained 3 manually discovered candidates after the fixes, producing the final 23-candidate set. This is a before/after tuning result, not an accuracy claim.

## What this establishes

The code-first workflow handles small and medium real repositories without executing them, preserves complete/partial/disabled coverage, produces bounded evidence, and can surface useful findings that raw secret or pattern scanning did not provide. It also demonstrates why human disposition remains necessary: broad sinks, ID lookups, external headers, and test credentials cannot be resolved from a pattern alone.

## Remaining evaluation gaps

- Repeat the process on owner-authorized private applications with production context and durable human dispositions.
- Add an independent manual-review sample to estimate false negatives instead of relying on findings discovered during tuning.
- Measure review time, time to first useful result, and within-project duplicate rate with evaluation instrumentation.
- Validate dependency findings separately with OSV enabled; advisory presence still does not establish reachability.
- Validate live Ollama/OpenAI investigation only after explicit resource or spend approval, and measure whether it improves reviewer decisions.
- Expand beyond current syntax-only, five-explicit-hop TypeScript/JavaScript coverage only from observed failures.

## 2026-09-09 owner-authorized scale pass

Two owner-authorized private Next.js repositories were scanned locally after the fixture pass. They are intentionally anonymous and no source or raw report is committed. AI and OSV network access were disabled; the installed Semgrep and Gitleaks adapters and the saved exact-version advisory database remained enabled.

| Measure                      | Repository A | Repository B |
| ---------------------------- | -----------: | -----------: |
| Supported files              |        1,196 |        1,039 |
| Supported source size        |     5.82 MiB |     5.25 MiB |
| Snapshot truncated           |           no |           no |
| Complete audit wall time     |       9.82 s |       6.62 s |
| Peak process resident memory |      574 MiB |      448 MiB |

The pass found two actionable detector-quality problems. Broad React prop taint produced 74 and 34 candidates; browser-source tracking and real navigation sinks reduced those sets to 2 and 9 without losing benchmark recall. Generic `.exec()` handling treated a regular-expression parser as command execution and produced 14 derived Next.js candidates; it now produces 0 for that path. Both regressions have benign tests. These are tuning results, not project security conclusions or generic accuracy claims.

Current snapshot limits are 4,000 supported files, 32 MiB total source, 2 MiB per source file,
4 MiB per dependency lockfile, depth 24, and 12,000 visited entries. Preflight reports predicted
truncation and requires explicit approval before a partial audit.

## 2026-09-10 five-project calibration pass

CodebaseScan was then run against five owner-authorized applications with different sizes and
structures. They remain labeled A-E; the private mapping, source snapshots, and raw reports are not
committed. Target code and configuration were parsed only as data. No target dependency, script,
test, build, or module was executed. AI and OSV network access were disabled. Installed Semgrep and
Gitleaks adapters plus the local advisory database were enabled.

The initial pass exposed repeated accessibility, privacy, reliability, SaaS error-response, and
generic object-lookup noise. Paired fixtures and structural changes were added before the final
pass. The final agent-plan contract also grouped findings sharing one rule and primary file without
dropping finding, fingerprint, or evidence references.

| Measure                  |       A |       B |                C |       D |       E |
| ------------------------ | ------: | ------: | ---------------: | ------: | ------: |
| Supported files analyzed |   1,196 |   1,070 |            1,500 |     425 |     192 |
| Snapshot                 |    full |    full | partial of 2,573 |    full |    full |
| Initial candidates       |     166 |      62 |              351 |       4 |       1 |
| Final candidates         |     130 |      13 |              201 |       4 |       0 |
| Initial agent tasks      |     112 |      74 |              383 |       9 |       3 |
| Final root-cause tasks   |      70 |      20 |              159 |       7 |       2 |
| Explicit coverage gaps   |       8 |       7 |               23 |       9 |       7 |
| Wall time                | 27.86 s | 18.36 s |          26.39 s |  9.01 s | 10.38 s |
| Peak resident memory     | 721 MiB | 596 MiB |          855 MiB | 353 MiB | 340 MiB |

Different repositories produced materially different outputs: A was dominated by local dependency
advisories and SaaS review candidates; B retained a small privacy-focused set; C exposed broad
authorization, Next.js, secret, accessibility, and maintainability review work but remained
explicitly partial; D retained four focused Semgrep candidates; E had no source finding while still
showing seven coverage gaps and two control-verification tasks. Zero findings therefore did not
render as a clean or certified result.

The reductions are detector-calibration and queue-compression results, not evidence that the
removed candidates were vulnerabilities or that the remaining candidates are confirmed. There are
still no durable owner dispositions or exhaustive independent false-negative reviews for this
five-project set. Synthetic fixture results remain separate from real-project quality claims.

Process wall time and peak resident memory are now captured externally for this pass. Review time,
time to first accepted result, manual misses, and accepted-finding cost remain unmeasured until
human disposition and optional AI evaluation begin.

## 2026-09-11 complete-snapshot calibration refresh

The current workflow-v32 build repeated the owner-authorized corpus after increasing the bounded
snapshot, excluding conventional generated output, and compacting the structural graph to resolved
local call edges. Package entrypoints that declare captured TypeScript through conventional
`dist`, `build`, `lib`, or `out` paths are mapped back to source without loading package code.

| Project                  | Files | Snapshot/profile | Findings                             | Tasks | Core coverage          |
| ------------------------ | ----: | ---------------- | ------------------------------------ | ----: | ---------------------- |
| seusaas-platform         | 1,200 | complete         | 29: 2 high, 2 medium, 23 low, 2 info |    39 | 14 complete, 2 partial |
| robs-web                 | 1,072 | complete         | 15: 11 medium, 1 low, 3 info         |    23 | 15 complete, 1 partial |
| capta-core               | 2,555 | complete         | 109: 15 high, 28 medium, 66 low      |   100 | 12 complete, 4 partial |
| aster-streaming-platform |   839 | complete         | 3: 1 low, 2 info                     |     9 | 14 complete, 2 partial |
| severyn                  |   314 | complete         | 0                                    |     3 | 14 complete, 0 partial |

The five reports cover 5,980 supported files and 156 source candidates with no snapshot or
structural-profile truncation. Bounded lockfile parent paths were retained for 4,945 of 5,141
resolved dependency records across the corpus. Remaining partial states are explicit bounded
mechanical-analysis retention or safe target-configuration limits; runtime Axe, HTTP, deployment,
and infrastructure evidence remains not performed, not run, or unsupported as applicable.

The versioned calibration aggregate still has zero independent candidate labels and zero completed
false-negative reviews, so `accuracyClaimReady` remains false. The fixture benchmark is a separate
regression gate: 55 true positives, zero false positives, and zero false negatives on declared
synthetic ground truth.
