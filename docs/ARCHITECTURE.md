# Architecture

## Process and trust boundaries

```text
Browser on loopback
        |
Next.js UI + guarded HTTP routes
        |
Application SQLite store <---------- Local CLI (register, queue, export)
        |
Single long-running worker
        |
LangGraph parent workflow <---------- Official SQLite checkpointer
        |
        +-- bounded source snapshot (read-only, raw content in memory)
        +-- deterministic pattern scanner
        +-- optional trusted Semgrep/Gitleaks processes
        +-- manifest inventory
        +-- contextual review subgraph
                    |
                    +-- snapshot-only source tool
                    +-- optional Ollama on loopback
```

Next.js never owns a long-running audit. The worker consumes persisted queued jobs, updates progress events, and handles cancellation independently of page lifecycle. The first version intentionally runs one audit at a time on one machine.

Application state uses Node's `node:sqlite`; graph checkpoints use the official `@langchain/langgraph-checkpoint-sqlite` adapter. They serve different responsibilities and use separate files. The application does not implement a custom partial checkpoint serializer. `better-sqlite3` is installed for the official adapter; no third-party native artifacts are bundled.

## Graph responsibilities

```text
START -> snapshot
              +-> patterns --+
              +-> semgrep ---+
              +-> gitleaks --+-> normalize
              +-> inventory-+       |
                              investigate (up to 12 candidates)
                                    |
                              prepare_report
                                    |
                              human_review [interrupt]
                                    |
                              publish -> END
```

The four scanner branches publish state updates through reducers. Fan-in waits for all four branches, including explicit skipped or failed results. Investigation is bounded by a deterministic candidate budget. It does not use an invented confidence threshold.

The nested review graph is:

```text
collect_context -> assess
       ^             |
       +-- request additional allowed files (at most 2 rounds)
                     |
                    END
```

The optional model requests exact source paths through structured output. Deterministic routing validates and dispatches snapshot reads; this is deliberately narrower than a free-form autonomous ReAct/shell loop. LangChain supplies the schema-backed tool and Ollama adapter. The graph supplies the repeatable process.

## State and persistence

Raw repository content is retained in a bounded in-process snapshot. It is not placed wholesale in application reports or graph checkpoints. Findings contain small redacted source excerpts and digests; these are still sensitive source-derived data.

A worker restart rebuilds the snapshot before further source analysis and compares its digest with the checkpoint. Mismatched source causes failure instead of mixing evidence. This is not an atomic Git snapshot; stop mutating the target during collection. A completed draft can be published against its recorded snapshot without re-reading the current repository.

`thread_id` is the audit UUID. The pure publication node calls `interrupt()`. Publication submits a rationale and resumes the same thread with `Command`. Nothing dangerous happens before or after the interrupt: publication is a report-state transition, not an exploit, deployment, or code change.

Replay is not an exactly-once guarantee. Nodes must be safe to repeat. Progress events have unique keys, normalized findings have deterministic IDs, and publication merges the current human dispositions instead of overwriting them with stale model state. Real crash-injection coverage remains a release gate.

## Evidence versus assessment

A finding stores original source/rule/severity, relative file locations, evidence digests, source excerpts, and an independent human disposition. An assessment may say likely issue, likely false positive, or inconclusive. It cannot remove or confirm the source finding. Confirmation is an explicit local analyst action with a rationale, not cryptographic proof or dynamic exploit verification.

Dependency declarations are a separate inventory type. They are not placed in the vulnerability domain until a real vulnerability matcher exists.

## HTTP boundary

The server wrapper binds to `127.0.0.1`. Proxy and API guards enforce exact loopback hosts. State-changing requests require same Origin, JSON, and the UI header. Bodies are bounded while streaming. Routes accept registered project IDs, never arbitrary source paths or model endpoints. The local OS user is trusted; there is no multi-user authentication. Never bind this application publicly or expose it through a tunnel/reverse proxy.

## Reading order

1. `src/domain/types.ts`: contracts and trust language.
2. `src/scanners/builtin.ts`: simple deterministic input/output.
3. `src/engine/review-graph.ts`: state and bounded conditional loop.
4. `src/engine/audit-graph.ts`: reducers, branches, fan-in, interrupt.
5. `src/engine/run.ts`: checkpoint thread lifecycle.
6. `src/server/store.ts` and `src/worker/main.ts`: application durability.
7. `src/components/audit-workspace.tsx`: real data and user decisions.
