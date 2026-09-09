# Architecture

## Process and trust boundaries

```text
Browser on loopback
        |
guarded Next.js UI/API <---------- local CLI / CI runner
        |
application SQLite (jobs, reports, budgets, AI cache)
        |
single long-running worker
        |
LangGraph audit workflow <-------- separate SQLite checkpointer
        |
        +-- bounded read-only source snapshot
        +-- deterministic project profile + AST security rules
        +-- Node.js supply-chain integrity checks
        +-- isolated dead-code + source quality reports
        +-- dependency structure + duplicate-code reports
        +-- built-in source patterns
        +-- application posture scanner
        +-- optional Semgrep / Gitleaks processes
        +-- lockfile inventory + optional fixed-host OSV API
        +-- optional approved HTTP response probe
        +-- bounded contextual review subgraph
                    |
                    +-- snapshot-only opaque-ID context broker
                    +-- disabled / loopback Ollama / opt-in OpenAI Responses API
```

Next.js never owns a long-running audit. The worker claims persisted jobs and handles cancellation independently of the browser. CI uses the same graph with an ephemeral store and skips only the human publication interrupt.

Application state uses Node `node:sqlite`. Graph checkpoints use `@langchain/langgraph-checkpoint-sqlite` in a separate file. Schema migration adds per-audit options, AI usage, content-addressed AI cache, and append-only report-revision tables without rewriting old reports. Reports and stored options are runtime-schema validated on write/read.

## Audit graph

```text
START -> snapshot
              +-> patterns ----+
              +-> project map -+
              +-> AST security +
              +-> Next security+
              +-> React security+
              +-> dependencies -+
              +-> duplication --+
              +-> supply chain -+
              +-> code quality --+
              +-> posture -----+
              +-> semgrep -----+
              +-> gitleaks ----+-> normalize/reconcile
              +-> OSV inventory+          |
              +-> HTTP probe --+     investigate (bounded, AI enabled)
                                            |         offline skips
                                      prepare_report
                                            |
                         interactive: human_review [interrupt]
                                            |
                                         publish -> END
                         CI: draft report ----------> END
```

The fifteen scanner/profile results publish through reducers. Fan-in waits for completed, partial, skipped, or failed status from every capability. When no reviewer is configured, the graph moves directly from normalization to report preparation. Plain TypeScript performs parsing, process execution, URL validation, normalization, and report transforms; LangGraph is reserved for lifecycle, parallelism, bounded context loops, persistence, branching, and human review.

The nested review graph remains:

```text
collect_context -> assess
       ^             |
       +-- allowed evidence/profile ID request (at most 2 rounds)
```

Repository text is untrusted. It cannot select tools, endpoints, headers, request bodies, or local paths. An AI assessment cannot delete a finding, change its source severity, confirm exploitability, or set the human disposition.

## Deterministic evidence

`project-profile.ts` parses captured TypeScript/JavaScript as data and maps Next.js, Express, tRPC, Prisma, Drizzle, Supabase, Auth.js, GraphQL, Zod, Joi, and Valibot signals plus entry points, symbols, imports, direct local call edges, and security facts under fixed limits. `ast-security.ts` uses those relationships for authentication, permission, and tenant/owner scope. It performs bounded local and selected five-hop request-flow checks for SQL/NoSQL, SSRF, redirects, process execution, filesystem paths, unsafe deserialization, dynamic regular expressions, property writes, mass assignment, uploads, webhook ordering, cookie attributes, and client/server configuration. `next-security.ts` and `react-security.ts` add framework-specific route, caching, response, client-navigation, browser-storage, messaging, rendering, and server/client-boundary rules. Target configuration, plugins, types, and dependencies are never loaded or executed.

`supply-chain.ts` parses package manifests and npm/pnpm/Yarn lockfiles as data. It reports high-risk lifecycle declarations, plaintext or unpinned dependency sources, missing/weak integrity, non-default registry hosts, and npm manifest/lock drift. Private registries and intentional local sources remain review candidates rather than automatic compromise claims.

`quality.ts` measures function complexity, size, and parameter count through the Traceward-owned TypeScript parser. Knip runs from a pinned local entry point in a temporary snapshot containing source files, a sanitized manifest without scripts, and a generated JSON configuration that disables every target plugin/config loader. Only bounded paths and symbols are retained. Existing `coverage-summary.json` and `lcov.info` aggregates can be imported; Traceward does not run target tests.

`mechanical.ts` stages runtime JavaScript/TypeScript only and invokes pinned dependency-cruiser and jscpd entry points with fixed arguments. It does not load target tool configuration. Reports retain bounded local module counts, cycles, orphan candidates, coupling hotspots, duplicate locations, and aggregate duplication metrics. Raw duplicate fragments are discarded. These observations never become security findings automatically.

`builtin.ts` retains small broad review patterns when structural analysis cannot decide. `posture.ts` adds conservative TypeScript/Node/Next checks for declared browser policies, sensitive cookies, CORS, and environment use. A decisive AST candidate replaces the same-location broad raw-SQL/cookie pattern to reduce duplicates. Every automatic control result is also mapped into a versioned checklist; missing runtime or infrastructure evidence remains unverified.

Snapshot files are classified as runtime, test, or example. Project profiling, AST, posture, dependency inventory, and Semgrep use runtime scope; Gitleaks retains all captured scopes because credentials in test/fixture code can still be exposed. Runtime files are prioritized during traversal, and the preflight UI reports the split before queuing. Only bounded aggregate `coverage/coverage-summary.json` and `coverage/lcov.info` files are admitted from the otherwise excluded generated coverage tree.

The HTTP probe is per audit and requires an approved URL. It accepts only HTTP(S), strips queries from stored display URLs, rejects credential-shaped query keys, blocks metadata/link-local/reserved destinations, requires explicit approval for non-loopback private networks, validates every DNS answer and redirect, and pins the selected address for the connection. It uses HEAD and only falls back to bounded GET for 405/501. Static and runtime findings are reconciled by attaching observed evidence; static evidence is not silently removed.

Lockfile inventory supports npm, pnpm, Yarn Classic, and Yarn Berry without running package-manager code and excludes recognized local npm/Yarn workspace packages from advisory queries. Exact-version records in the compact local advisory database are used without network access. Manual refresh is separately opt-in, uses the fixed OSV API host, and sends only package name/version pairs. Pagination and advisory fetches have fixed request/result limits. Full responses are compacted, aliases are consolidated, withdrawn records are ignored, package-level severity is retained, CVSS v3 vectors are scored when labels are absent, and cache/report data distinguish source-reference hints from runtime reachability or exploitability.

## AI boundary

`TRACEWARD_AI` selects exactly one of `disabled`, `ollama`, or `openai`; there is no fallback. Ollama stays fixed to loopback. OpenAI uses the Responses API with JSON Schema structured output and `store: false`.

The context broker exposes a finding-specific catalog of opaque evidence, entry-point, symbol, fact, and resolved-call IDs. Models cannot name arbitrary repository paths. Delivery is checked against the immutable captured snapshot, rejects unknown/repeated IDs, permits at most two requested items per round, and caps accumulated source context at 16,000 characters. Context is redacted again for credentials, emails, and user-home paths; `.env` and key files never enter the snapshot.

Calls are protected by persisted per-audit call/input/output budgets, a per-finding limit, bounded retry/timeout policy, and a seven-day cache keyed by prompt version, model, finding fingerprint, evidence digests, and context digest. Reports record provider, model, prompt version, delivered IDs/files, truncation, redaction result, tokens, cache use, and configured-price cost approximation. Model output includes controls found, missing evidence, impact, preconditions, remediation choices, and safe verification steps; it remains an assessment only.

## Evidence, assessment, disposition, and coverage

A finding keeps detector, scanner/rule/version, original severity, file/line evidence, evidence kind, detection time, confidence, probable exposure, review priority, optional runtime/advisory metadata, optional AI assessment/provenance, and optional human review. Human dispositions include confirmed, fixed, false positive, accepted risk, and needs review. Expiring project exceptions keep the original finding and exact fingerprint visible. Checklist controls separately retain their deterministic status and an optional human assessment for verified external evidence, accepted gaps, non-applicability, or follow-up. These states are not collapsed into “verified.”

Coverage uses explicit capability states: `COMPLETE`, `PARTIAL`, `FAILED`, `DISABLED`, `NOT RUN`, `NOT SUPPORTED`, and `NOT PERFORMED`. Zero findings and a failed scanner are therefore different results. Traceward does not compute a global security score.

## Persistence and replay

The in-process snapshot is bounded and raw content is not stored wholesale in the application report. Findings contain small redacted excerpts and digests, which are still sensitive. A resumed graph recaptures source and rejects a changed digest instead of mixing snapshots.

Nodes are safe to repeat but execution is not a universal exactly-once guarantee. Event keys and finding fingerprints are deterministic. AI budgets are persisted before requests. Checkpoints carry workflow/config compatibility data and incompatible resumes fail closed. Workflow and human-review report states are appended to immutable revision rows while the audit points to the latest validated report. Publication merges current human dispositions. Actual worker `SIGKILL` recovery is tested; parser processes still require OS-level containment for hostile repositories.

## Local HTTP service

The Traceward UI binds to `127.0.0.1`. Its own API enforces loopback Host/URL, same Origin for mutations, JSON, a UI header, and streamed body limits. This control is separate from the optional outbound target probe. The application has no multi-user authentication and must not be exposed publicly.

## Reading order

1. `src/domain/types.ts`, `checklist.ts`, `report-schema.ts`, `coverage.ts`, and `provenance.ts`
2. `src/security/paths.ts`, `url-policy.ts`, and `redact.ts`
3. `src/scanners/project-profile.ts`, `ast-security.ts`, `next-security.ts`, `react-security.ts`, `supply-chain.ts`, `quality.ts`, `mechanical.ts`, `posture.ts`, `http-probe.ts`, `inventory.ts`, and `osv.ts`
4. `src/engine/context-broker.ts`, `review-graph.ts`, `openai.ts`, and `audit-graph.ts`
5. `src/server/store.ts`, `src/worker/main.ts`, `src/cli/main.ts`, and `src/cli/doctor.ts`
6. `src/components/audit-workspace.tsx` and `finding-details.tsx`
