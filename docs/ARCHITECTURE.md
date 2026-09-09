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
        +-- built-in source patterns
        +-- application posture scanner
        +-- optional Semgrep / Gitleaks processes
        +-- lockfile inventory + optional fixed-host OSV API
        +-- optional approved HTTP response probe
        +-- bounded contextual review subgraph
                    |
                    +-- snapshot-only source tool
                    +-- disabled / loopback Ollama / opt-in OpenAI Responses API
```

Next.js never owns a long-running audit. The worker claims persisted jobs and handles cancellation independently of the browser. CI uses the same graph with an ephemeral store and skips only the human publication interrupt.

Application state uses Node `node:sqlite`. Graph checkpoints use `@langchain/langgraph-checkpoint-sqlite` in a separate file. Schema migration adds per-audit options, AI usage, and content-addressed AI cache tables without rewriting old reports.

## Audit graph

```text
START -> snapshot
              +-> patterns ----+
              +-> posture -----+
              +-> semgrep -----+
              +-> gitleaks ----+-> normalize/reconcile
              +-> OSV inventory+          |
              +-> HTTP probe --+     investigate (bounded)
                                            |
                                      prepare_report
                                            |
                         interactive: human_review [interrupt]
                                            |
                                         publish -> END
                         CI: draft report ----------> END
```

The six branches publish results through reducers. Fan-in waits for completed, partial, skipped, or failed status from every capability. Plain TypeScript performs parsing, process execution, URL validation, normalization, and report transforms; LangGraph is reserved for lifecycle, parallelism, bounded context loops, persistence, branching, and human review.

The nested review graph remains:

```text
collect_context -> assess
       ^             |
       +-- exact allowed path request (at most 2 rounds)
```

Repository text is untrusted. It cannot select tools, endpoints, headers, request bodies, or local paths. An AI assessment cannot delete a finding, change its source severity, confirm exploitability, or set the human disposition.

## Deterministic evidence

`builtin.ts` retains small broad review patterns. `posture.ts` adds conservative TypeScript/Node/Next checks for declared browser policies, sensitive cookies, CORS, route/server-action authentication and authorization, tenant/owner scope, and environment use. It intentionally reports candidates when wrappers, platform behavior, middleware, or runtime policy cannot be proved.

The HTTP probe is per audit and requires an approved URL. It accepts only HTTP(S), strips queries from stored display URLs, rejects credential-shaped query keys, blocks metadata/link-local/reserved destinations, requires explicit approval for non-loopback private networks, validates every DNS answer and redirect, and pins the selected address for the connection. It uses HEAD and only falls back to bounded GET for 405/501. Static and runtime findings are reconciled by attaching observed evidence; static evidence is not silently removed.

Lockfile inventory supports npm, pnpm, Yarn Classic, and Yarn Berry without running package-manager code. OSV is separately opt-in and uses a fixed API host. Only package name/version pairs leave the machine. Full advisory responses are compacted, aliases are consolidated, withdrawn records are ignored, and cache/report data never claim reachability.

## AI boundary

`TRACEWARD_AI` selects exactly one of `disabled`, `ollama`, or `openai`; there is no fallback. Ollama stays fixed to loopback. OpenAI uses the Responses API with JSON Schema structured output and `store: false`.

Cloud context is limited to at most two already-selected files per round and 16,000 context characters, then redacted again for credentials, emails, and user-home paths. `.env` and key files are excluded. Calls are protected by persisted per-audit call/input/output budgets, a per-finding limit, bounded retry/timeout policy, and a seven-day cache keyed by prompt version, model, finding fingerprint, evidence digests, and context digest. Reports record provider, model, prompt version, files sent, redaction result, tokens, cache use, and configured-price cost approximation.

## Evidence, assessment, disposition, and coverage

A finding keeps detector, scanner/rule/version, original severity, file/line evidence, evidence kind, detection time, optional runtime/advisory metadata, optional AI assessment/provenance, and optional human review. These states are not collapsed into “verified.”

Coverage uses explicit capability states: `COMPLETE`, `PARTIAL`, `FAILED`, `DISABLED`, `NOT RUN`, `NOT SUPPORTED`, and `NOT PERFORMED`. Zero findings and a failed scanner are therefore different results. Traceward does not compute a global security score.

## Persistence and replay

The in-process snapshot is bounded and raw content is not stored wholesale in the application report. Findings contain small redacted excerpts and digests, which are still sensitive. A resumed graph recaptures source and rejects a changed digest instead of mixing snapshots.

Nodes are safe to repeat but execution is not a universal exactly-once guarantee. Event keys and finding fingerprints are deterministic. OpenAI budgets are persisted before requests. Publication merges current human dispositions. Abrupt termination and parser processes still require OS-level containment for hostile repositories.

## Local HTTP service

The Traceward UI binds to `127.0.0.1`. Its own API enforces loopback Host/URL, same Origin for mutations, JSON, a UI header, and streamed body limits. This control is separate from the optional outbound target probe. The application has no multi-user authentication and must not be exposed publicly.

## Reading order

1. `src/domain/types.ts`, `coverage.ts`, and `provenance.ts`
2. `src/security/paths.ts`, `url-policy.ts`, and `redact.ts`
3. `src/scanners/posture.ts`, `http-probe.ts`, `inventory.ts`, and `osv.ts`
4. `src/engine/review-graph.ts`, `openai.ts`, and `audit-graph.ts`
5. `src/server/store.ts`, `src/worker/main.ts`, and `src/cli/main.ts`
6. `src/components/audit-workspace.tsx` and `finding-details.tsx`
