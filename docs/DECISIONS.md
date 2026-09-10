# Initial engineering decisions

| Decision                                             | Rationale / consequence                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Local-first, single user                             | Avoid uploading proprietary repositories and avoid premature SaaS infrastructure. No public hosting mode.                                                                                                                                                                                                                       |
| Next.js + TypeScript                                 | Strong product UI and shared readable domain contracts. Node 22.16+ enables the selected native TypeScript/SQLite execution path.                                                                                                                                                                                               |
| Separate worker                                      | Audits and human-resume requests survive browser closure. No fire-and-forget audit in a route handler.                                                                                                                                                                                                                          |
| SQLite, one consumer                                 | Minimal setup for one machine. Not a distributed queue or multi-host deployment architecture.                                                                                                                                                                                                                                   |
| Official LangGraph SQLite saver                      | Learn real framework persistence; do not simulate checkpoints using a JSON file.                                                                                                                                                                                                                                                |
| No AI by default                                     | A reproducible demo must not require hardware, model downloads, keys, or fake model activity.                                                                                                                                                                                                                                   |
| Explicit Ollama or OpenAI provider                   | Ollama is fixed to loopback. OpenAI is opt-in, uses bounded redacted context, structured output, no tools, and `store=false`.                                                                                                                                                                                                   |
| Separate network opt-ins                             | OSV, OpenAI, and the one-URL HTTP probe are independently enabled; enabling one never authorizes another.                                                                                                                                                                                                                       |
| Patterns + posture + optional scanners               | Built-in candidates, application-posture checks, Semgrep, Gitleaks, and lockfile-based OSV matching expose distinct coverage.                                                                                                                                                                                                   |
| Safe HTTP posture probe                              | One explicitly approved URL, HEAD-first, bounded redirects/time/bytes, DNS validation and IP pinning; no crawl or exploitation.                                                                                                                                                                                                 |
| Source snapshot before analysis                      | Give tools a bounded fixed in-memory view and evidence digests. Exclude credentials files and unsupported inputs.                                                                                                                                                                                                               |
| No shell or target execution                         | Scanner subprocesses are trusted fixed binaries, not model-chosen commands or target scripts.                                                                                                                                                                                                                                   |
| No automatic exploit or fix                          | Verification means evidence review, not a claim of exploitation. Future dynamic tests require a separate threat model.                                                                                                                                                                                                          |
| No numeric security score                            | A high number could imply assurance unsupported by coverage. Display findings, coverage, and dispositions instead.                                                                                                                                                                                                              |
| Explicit coverage states                             | COMPLETE, PARTIAL, FAILED, NOT RUN, DISABLED, NOT SUPPORTED, and NOT PERFORMED prevent missing analysis from looking clean.                                                                                                                                                                                                     |
| AI cannot change scanner truth                       | Model output adds contextual assessment only; it cannot suppress findings, lower scanner severity, or publish a report.                                                                                                                                                                                                         |
| Human publication separate from finding confirmation | Reviewing a report must not falsely confirm every candidate.                                                                                                                                                                                                                                                                    |
| Explicit limitations in every export                 | Portable artifacts must preserve uncertainty even when viewed outside the app.                                                                                                                                                                                                                                                  |
| Custom CSS and system fonts                          | Small UI dependency surface, offline assets, readable components. No forced component library migration.                                                                                                                                                                                                                        |
| Apache-2.0 for original starter                      | Explicit open-source intention. External binary, rules, and model licenses must be reviewed separately.                                                                                                                                                                                                                         |
| No bundled binary/model/font files                   | Keep redistribution auditable and the starter lightweight.                                                                                                                                                                                                                                                                      |
| Pinned mechanical scanner packages                   | dependency-cruiser and jscpd run offline from Traceward-owned dependencies with fixed arguments; target scanner configuration is never loaded.                                                                                                                                                                                  |
| Isolated Knip execution                              | Knip receives captured source, script-free sanitized workspace manifests, and a generated config that disables all target plugins. Bounded declarative exclusions, aliases, workspaces, and entry hints reduce noise without executing target configuration. Its output is maintenance evidence, never a vulnerability verdict. |
| Declarative SaaS semantics                           | A root JSON/JSONC file may extend fixed identifier/helper lists and constrained public routes. It cannot provide code, regex, plugins, arbitrary paths, or suppressions. The declared name must still appear in captured source, and coverage/limitations remain visible.                                                       |
| Optional report schema v5 data                       | New audits add supply-chain and code-quality analysis. Stored v1-v4 reports remain readable, are not rewritten, and omit optional fields. Workflow v5 prevents old in-progress checkpoints from resuming into changed deterministic analysis.                                                                                   |

Changes to these decisions should be deliberate. Add a dated decision with the problem, alternatives, trade-offs, and migration impact. Do not create endless documentation for ordinary implementation details.

## 2026-09-10 — explicit framework-major rule coverage

Captured package manifests provide requested versions as data; Traceward never imports them. The
project profile reports a supported, partial, or unverified static-rule coverage state for detected
Next.js, React, and Express majors. Ambiguous ranges and source-only detections remain unverified,
and frameworks without a declared version matrix never inherit a compatibility claim. Workflow v21
prevents older checkpoints from being resumed as if they contained this metadata.

## 2026-09-10 — declared package component ownership

Every captured root or nested package manifest defines a bounded component. The profiler assigns
source entities to the nearest manifest root and records resolved imports that cross components.
This is package ownership evidence, not proof of process, network, tenant, or deployment isolation.
Opaque component IDs remain stable for the same manifest/name pair, while reports resolve them to
human-readable package names. Workflow v22 prevents incompatible checkpoint reuse.

## 2026-09-10 — security-critical test relationships

Captured test imports are followed through at most five resolved source hops to entry-point and
sensitive-operation files. This is prioritization evidence, never a coverage percentage or proof of
an assertion. URL-only end-to-end tests remain unattributed. The result is a separate bounded JSON
artifact and creates no vulnerability finding. Report schema v9, release-readiness pack 0.5.0, and
workflow v23 preserve the new state and its limitations.

## 2026-09-10 — agent plan contract v2

The remediation plan is now also emitted as the primary `agent-plan.json`, with a generated JSON
Schema. Version 2 adds cause grouping, explainable priority factors, confidence, exposure, change
risk, automatic-fix eligibility, human-authorization flags, expected changes, and structured
verification-command allowlists. `remediation-plan.json` remains a byte-identical filename alias so
existing report consumers can move deliberately; its payload also carries schema version 2. Version
1 plans were external generated artifacts rather than stored audit state and are not rewritten.

## 2026-09-10 — applied rule quality artifact

Rule quality is emitted separately as `rule-quality.json` plus a JSON Schema. It reports only rules
that produced findings in the audit, keeps fixture measurements separate from real-project human
dispositions, and states detector limitations instead of presenting one unsupported accuracy score.

## 2026-09-10 — intrinsic JSX accessibility semantics

Static accessibility rules preserve JSX tag casing. A React component such as `Input` is not
treated as the intrinsic `input` element, and an intrinsic wrapper forwarding spread attributes is
left unverified because its accessible name may be supplied by the caller. Exact static or dynamic
`htmlFor`/`id` expressions remain linkable. Scanner version 0.2.0 and workflow v14 prevent old
results from being presented as current calibration.

## 2026-09-10 — corpus-calibrated privacy and reliability semantics

Privacy log analysis inspects payload expressions rather than matching sensitive words in static
human-readable messages. Template interpolations remain analyzable. Reliability rule TW-REL002 now
means an undocumented empty catch; a comment explaining a narrow intentional ignore is retained as
review context without becoming a finding. The scanners and audit-mode pack move to 0.2.0 and the
workflow moves to v15.

## 2026-09-10 — structural caught-error exposure

TW-SAAS004 now requires an AST value reference to the catch binding. A response property named
`error` with a constant public code is no longer mistaken for exposure merely because its key has
the same text. Direct objects, messages, stacks, causes, and helper calls receiving the caught value
remain review candidates. SaaS scanner and mode-pack versions move to 0.3.0; workflow moves to v16.

## 2026-09-10 — agent plan contract v3 grouping

Agent-plan version 3 groups unresolved non-dependency findings that share task kind, source rule, and
primary file. Every original finding, fingerprint, evidence ID, severity, and file stays referenced;
only repetitive work items collapse. Task IDs now derive from the stable group key, so version 2
consumers must regenerate plans from their immutable audit report rather than mixing task IDs.

## 2026-09-10 — declared context and observed data map

Safe Traceward JSON/JSONC configuration may add bounded project context and manifest-verified script
names. The audit still executes neither configuration nor scripts. Declared context keeps separate
provenance from an observed, source-derived data map. Both fields are optional additions to report
schema v5, so stored earlier reports remain readable and are not rewritten. Workflow v11 prevents an
in-progress older graph from resuming into the changed profiler behavior.

## 2026-09-10 — bounded static audit modes

Accessibility, privacy, and reliability start as small Traceward-owned AST scanners rather than new
third-party engines. Their nine rules have declared vulnerable and benign benchmark cases and retain
source-only limitations. They add optional findings to report schema v5 without rewriting existing
reports. Workflow v12 prevents old in-progress checkpoints from resuming into the expanded fan-out.

## 2026-09-10 — explicit mode selection

All eight offline modes run when no selection is supplied. CLI/API callers may choose a bounded
subset; unrelated graph nodes still publish explicit skipped runs so coverage becomes `DISABLED`
rather than clean. Reports store the versioned selection. Stored options and reports gain optional
fields only, while workflow v13 protects in-progress checkpoint compatibility.

## 2026-09-10 — agent plan contract v4 risk paths

Agent-plan tasks carry bounded `riskPathIds` when their findings belong to a statically resolved
entrypoint-to-operation path. A version 2 task bundle embeds only those related paths and expands
its bounded project context with their files. The links are navigation evidence, not runtime or
exploitability claims. Version 3 plan and version 1 bundle consumers must regenerate artifacts from
the immutable audit report.

## 2026-09-10 — sanitized environment contract

Environment examples, samples, and templates enter the snapshot only after every value and comment
is discarded; real `.env` files remain excluded. Workflow v20 compares the retained names with
bounded `process.env`, `import.meta.env`, and direct destructuring accesses. A missing name becomes
a low-severity review candidate only when at least one template was captured. Without a template,
names stay unverified instead of being reported as defects. Report schema v8 and audit-mode pack
0.4.0 preserve this behavior for downstream consumers. Rule-quality schema v2 accepts the new
source and records its paired benchmark scope.

## 2026-09-10 — agent plan contract v5 component context

Every remediation task now carries bounded owning-component IDs and exact critical source targets
that have captured test-reference evidence. Task-bundle version 3 adds only those targets plus the
selected components and their immediate cross-component edges. Neighbor component metadata is
included so an edge never points at an unknown package. Static import relationships remain
navigation evidence rather than proof of executed assertions or behavioral coverage.

## 2026-09-10 — inert OpenAPI/source consistency

Captured OpenAPI and Swagger JSON/YAML are parsed as data and compared with statically mapped
Next.js and Express operations by HTTP method and normalized parameterized path. External
references and generators are never loaded. Declared-only and source-only records stay
documentation-consistency candidates rather than vulnerability findings. Unmatched source routes
count only inside the common static path scope of a captured specification; all others remain
visible but unassessed. Report schema v10, workflow v24, and audit-mode pack 0.6.0 make the new
persisted output explicit.

## 2026-09-10 — inert database contract correlation

Prisma model blocks, literal Drizzle table declarations, SQL table statements, and mapped source
call chains are correlated without loading an ORM or database. A comparison gap is created only
when the corresponding captured schema or migration side exists; otherwise coverage remains
unsupported. Files ending in .prisma join the bounded text snapshot. Report schema v11, workflow
v25, and audit-mode pack 0.7.0 preserve the new output for consumers.
