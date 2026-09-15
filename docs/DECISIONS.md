# Initial engineering decisions

## 2026-09-11 — deterministic product core and external agent boundary

CodebaseScan no longer embeds a model runtime, LangChain, or LangGraph. The product's primary
contract is a deterministic CLI that captures authorized source as data, runs bounded scanners, and
updates one portable static report. This keeps installation, offline operation, CI behavior, cost,
and scanner evidence predictable.

Deeper investigation belongs to the user's separately authorized coding agent. Static packages
export versioned agent reports, rules, plans, schemas, and artifact hashes; the bundled Codex skill
teaches one compatible workflow. An external agent may inspect the working tree only under its own
authorization and must keep hypotheses, review decisions, and corrections separate from
deterministic findings.

The default report root now represents current state instead of product-managed history. Users who
need retention can version the directory, preserve a baseline JSON, or store CI artifacts. Legacy
report indexes remain readable during migration.

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
| Shadcn primitives and system fonts                   | Shared typed primitives keep the application UI consistent without remote font assets. Feature components and the portable static report remain separate presentation layers.                                                                                                                                                   |
| MIT for the public project                           | Keep contribution and reuse terms simple. External binaries, rules, models, and dependencies retain their own licenses and must be reviewed separately.                                                                                                                                                                         |
| No bundled binary/model/font files                   | Keep redistribution auditable and the starter lightweight.                                                                                                                                                                                                                                                                      |
| Pinned mechanical scanner packages                   | dependency-cruiser and jscpd run offline from CodebaseScan-owned dependencies with fixed arguments; target scanner configuration is never loaded.                                                                                                                                                                               |
| Isolated Knip execution                              | Knip receives captured source, script-free sanitized workspace manifests, and a generated config that disables all target plugins. Bounded declarative exclusions, aliases, workspaces, and entry hints reduce noise without executing target configuration. Its output is maintenance evidence, never a vulnerability verdict. |
| Declarative SaaS semantics                           | A root JSON/JSONC file may extend fixed identifier/helper lists and constrained public routes. It cannot provide code, regex, plugins, arbitrary paths, or suppressions. The declared name must still appear in captured source, and coverage/limitations remain visible.                                                       |
| Optional report schema v5 data                       | New audits add supply-chain and code-quality analysis. Stored v1-v4 reports remain readable, are not rewritten, and omit optional fields. Workflow v5 prevents old in-progress checkpoints from resuming into changed deterministic analysis.                                                                                   |

Changes to these decisions should be deliberate. Add a dated decision with the problem, alternatives, trade-offs, and migration impact. Do not create endless documentation for ordinary implementation details.

## 2026-09-10 — rename to CodebaseScan before publication

The project, package, CLI, environment variables, local state, report folders, and portable artifact
identifiers move from Traceward to CodebaseScan before the first public release. The old name is
already used by unrelated products, while CodebaseScan states the tool's source-audit scope more
directly. This is a pre-release breaking rename: existing local databases, checkpoints, generated
reports, and configuration filenames are not migrated or resumed across names. Regenerate them with
the CodebaseScan build instead of mixing old and new state.

## 2026-09-10 — typed UI foundation

The persistent Next.js application adopts Tailwind CSS and local shadcn primitives under
`src/components/ui`. Feature-level audit presentation remains under `src/components`, and the
script-free static report keeps its independent renderer. Existing visual behavior is preserved
while new screens can grow from reusable typed components. System fonts remain the default so the
local interface never depends on a font download.

## 2026-09-10 — explicit framework-major rule coverage

Captured package manifests provide requested versions as data; CodebaseScan never imports them. The
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

Safe CodebaseScan JSON/JSONC configuration may add bounded project context and manifest-verified script
names. The audit still executes neither configuration nor scripts. Declared context keeps separate
provenance from an observed, source-derived data map. Both fields are optional additions to report
schema v5, so stored earlier reports remain readable and are not rewritten. Workflow v11 prevents an
in-progress older graph from resuming into the changed profiler behavior.

## 2026-09-10 — bounded static audit modes

Accessibility, privacy, and reliability start as small CodebaseScan-owned AST scanners rather than new
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

## 2026-09-10 — component-aware lifecycle diff v2

Report comparison keeps exact fingerprint semantics but now accepts earlier same-project reports.
A finding is reappeared only when absent from the selected base, present in current, and present
with the same fingerprint in supplied history. New, resolved, unchanged, recurring, severity,
disposition, and ownership changes are summarized by captured component. Multi-component evidence
counts in each owner and remains explicit in the comparison limitations.

## 2026-09-10 — bounded webhook contract correlation

Mapped webhook routes now retain resolved call-edge, signature-verification, idempotency, and
literal event-name evidence. Literal names produced and consumed locally are paired; one-sided names
remain explicit external boundaries rather than mismatch findings. Callback routes require
verification evidence so ordinary OAuth callbacks are excluded. Report schema v12, investigation
bundle v3, workflow v26, and audit-mode pack 0.8.0 preserve the output for consumers.

## 2026-09-10 — inert feature flag consistency

Primitive JSON feature maps and literal TypeScript definition collections are correlated with a
narrow allowlist of evaluation and definition-by-key calls. Dynamic keys remain unpaired. Defaults
retain type and digest while arbitrary strings stay out of reports. Different declaration files may
represent valid plan/environment variants and do not conflict by themselves. Report schema v13,
investigation bundle v4, workflow v27, and audit-mode pack 0.9.0 preserve the new output.

## 2026-09-10 — separate run and coverage manifest

Static exports include a schema-validated compact manifest before the larger evidence artifacts.
It records product/workflow/pack versions, mode selection, snapshot limits, scanner duration and
status, explicit coverage states, limitations, and output digests. The existing outer artifact
manifest digests this run manifest, avoiding a circular self-digest while preserving integrity.

## 2026-09-10 — deterministic built-in policy profiles

Advisory never blocks, balanced gates high-confidence high/critical work and adopts baselines using
new-only findings, and strict includes existing medium-or-higher debt. Failed/truncated coverage
blocks balanced; partial coverage also blocks strict. Optional and unsupported product capabilities
stay visible without making every static audit fail. Exit 1 means finding failure and exit 2 means
blocking coverage or operational failure; `policy-result.json` distinguishes the latter cases.

## 2026-09-10 — exact portable suppression ledger

Portable suppressions are separate explicitly supplied data, not executable project configuration.
They match project, fingerprint, rule, paths, and evidence-file digests; expired, stale, and absent
targets remain counted without changing the finding. Owner, justification, supporting evidence,
creation, and optional expiry are required/preserved. Identity remains unauthenticated and visible
as a limitation until signed reviewer policy exists.

## 2026-09-10 — dependency lifecycle identity v3

Comparison schema v3 and remediation-result schema v2 stop using lockfile source lines to decide
whether a dependency advisory remained present. Dependency lifecycle identity is now the advisory
source and ID, package, resolved version, and lockfile. This keeps the exact finding fingerprint for
evidence, AI cache, review, and suppression boundaries while preventing an unrelated lockfile line
shift from inventing resolved and new advisories. Other findings retain exact fingerprint matching;
old comparison and remediation-result artifacts remain immutable and are not mixed with the new
counts.

## 2026-09-10 — external correction evidence ledger

Project test and build execution remains outside the audit trust boundary. A separately authorized
executor may supply a strict versioned ledger bound to the project, baseline audit, after audit,
both snapshot digests, and the exact baseline agent-plan artifact digest. Only exact project-context
commands from that plan are applied; other records remain unmatched. Raw output is rejected in
favor of exit code, duration, byte count, and SHA-256 metadata. Remediation-result schema v3 records
the ledger and keeps an otherwise resolved task partial when declared verification is incomplete.
`finalize` combines existing artifacts without rerunning the target. Executor authentication and
changed-file attestation remain explicit future work.

## 2026-09-10 — stable static report root

Every terminal audit remains an immutable directory keyed by audit ID. A versioned
`report-index.json` and script-free root `index.html` are updated atomically and link the newest
result plus bounded history. Users can keep one local bookmark or host the complete report root as
static files without running the review application. The report still contains sensitive evidence
and has no access-control layer; hosting is an explicit user decision.

## 2026-09-10 — small terminal installation boundary

The packaged CLI keeps deterministic scanners and LangGraph core as runtime dependencies. Next.js,
React, shadcn UI dependencies, SQLite checkpoint persistence, and the Ollama adapter are development
or optional peer dependencies. One-shot terminal audits use an in-memory checkpointer; the
persistent review application keeps SQLite. Clean installs are exercised with npm, pnpm, and Yarn
on Node 22.16 and npm on Node 24. Linux/WSL is the supported 0.2 environment; native Windows and
macOS remain unclaimed until their own path, process, and package-manager gates exist.

## 2026-09-10 — external runtime accessibility evidence

CodebaseScan does not start or navigate the target application. An authorized external browser
runner may place a standard Axe JSON artifact at the project root. The snapshot imports bounded
violation groups, removes selectors and raw HTML, and reports exactly which artifact was used.
Absence is `NOT PERFORMED`, never a clean accessibility result.

## 2026-09-10 — source-only web posture mode

The ninth default mode correlates React/Next.js root entries with robots, sitemap, Next.js metadata,
and optional llms.txt declarations. Monorepo package roots and Next.js root route groups are
recognized without treating nested routes as separate applications. Missing declarations are
informational review candidates because source cannot prove whether an app is public or how a
deployment behaves. Workflow v29, audit-mode pack 1.0.0, report schema v15, and report-index schema
v1 identify this behavior.

## 2026-09-10 — guarded npm release provenance

The package declares public npm access and provenance metadata while retaining `private: true`
until an explicit publication decision. The repository URL must remain the exact public GitHub
source. The first release requires a clean release gate and deliberate removal of the private guard;
no commit or CI event in normal development can publish the package.

## 2026-09-11 — independent calibration contract

Detector output, ordinary human dispositions, and detector-quality ground truth are separate
artifacts. A calibration entry binds to the exact audit, snapshot, finding fingerprint, and source
digests. It records candidate outcome plus evidence, location, and explanation ratings. Manual
misses have their own bounded relative paths. Aggregates anonymize project names and omit source.
Precision is descriptive for reviewed decided candidates; recall is withheld unless every project
declares a complete false-negative review. The aggregate cannot advertise readiness while reviews
are incomplete or inconclusive.

## 2026-09-11 — structural scanners replace broad fallback evidence

Broad source patterns remain useful when structural parsing is unavailable, but they must not
duplicate a stronger structural result from the same parsed file. Generic ID-lookup hotspots are
therefore retained only as fallback evidence outside structurally analyzed files. The Next.js input
validation rule now requires a state-changing operation; database reads no longer make a POST route
a mutation candidate by themselves. Scanner versions change with detector behavior so the local
cache cannot replay obsolete results.

## 2026-09-11 — bounded runtime form observation

The optional HTTP probe may inspect form metadata from the single explicitly approved HTML
response. It follows no links, submits no form, retains no field value, and applies the same
DNS/IP/redirect/body/time limits as the existing probe. Source-only audits remain unchanged and
the absence of a probe remains `NOT RUN`.

## 2026-09-11 — larger complete snapshots and compact report history

The default bounded snapshot now accepts at most 4,000 supported files, 32 MiB total source, 2 MiB
per ordinary source file, and 4 MiB per lockfile. Conventional generated, Pagefind, build, and
framework output stays excluded. This covers the current five-project corpus without truncation;
larger repositories must explicitly accept partial coverage until sharding exists. Static packages
write a small integrity-checked index entry for root history, while trusted report readers accept a
complete audit report up to 64 MiB. The root index never embeds the full large report.

## 2026-09-11 — calibrated structural interpretation

Broad lexical rules use TypeScript-parsed comment ranges so a template literal cannot make later
comments look executable. Next.js validation follows captured reachable helpers and Server Action
parameters. React client-boundary rules distinguish visual design values from credentials and
treat `usePathname()` as a server-controlled current-path source. Project profiles retain only
resolved local call edges and recover captured TypeScript workspace entrypoints from conventional
`dist`, `build`, `lib`, or `out` declarations. Each behavior has a benign regression fixture and
target code remains inert data.

## 2026-09-11 — profile-aware cache and current report schema

Every deterministic scanner that consumes the project profile includes the profile scanner version
in its cache variant. Workflow v31 invalidates earlier checkpoints and cache entries so a newer
profile cannot be combined with stale downstream findings or coverage. Report schema version 16 is
centralized and portable review/suppression imports emit the current schema instead of downgrading
the report.

## 2026-09-11 — bounded multi-manager dependency paths

Dependency remediation now derives parent paths from captured npm v1/v2/v3 package graphs, pnpm
importers/snapshots, and Yarn Classic/Berry dependency stanzas. Traversal retains at most three
paths per resolved package, limits each path to twelve package hops, and stops after 20,000 queued
routes. npm hoisting and nested installs are resolved against captured package entries. Repeated
workspace declarations remain separate roots. An unresolved Yarn selector produces no inferred
path. No package manager, lifecycle script, or target configuration executes.

## 2026-09-11 — synchronized declared fixture metrics

Rule-quality schema v3 marks a rule as fixture-measured only when that exact scanner/rule pair is
present in declared benchmark ground truth. A repository test reconstructs the expected catalog
from every `ground-truth.json` file and fails on missing or stale entries. Dynamic execution now has
its own inert positive fixture paired with the existing comment-only negative fixture. Synthetic
metrics remain separate from independent real-project calibration.

## 2026-09-11 — agent review contract and bounded repository investigation

Agent review is an optional layer over deterministic evidence, not a replacement scanner.
`agent-report.json` combines the remediation plan with a versioned generic rule pack and explicit
quick, standard, and deep workflows. Standard and deep LangGraph review may search only bounded
plain text from the immutable captured snapshot; search matches receive opaque IDs and remain
untrusted evidence. LangChain supplies the structured local-model adapter, while the controlled
OpenAI adapter keeps direct storage, timeout, retry, cache, and token-budget enforcement. A bundled
Codex skill may inspect an authorized working tree outside the built-in snapshot loop, but it must
verify report hashes, apply the same rules, and keep new hypotheses separate from detector output.
Workflow v33 and report schema v17 identify the changed persisted behavior.

## 2026-09-15 — separate application context for external agents

The portable report now emits `agent-context.json` and its JSON Schema beside the existing agent
report, rules, and plan. This additive contract records observed framework and security signals,
declared project context, explicit unknowns, and incomplete coverage without changing scanner
findings. Authentication code, cookie evidence, client token state, cross-document messaging,
framing policy, and CSRF evidence remain separate signals. In particular, CSRF is not promoted from
an authentication-shaped finding unless browser-managed credentials and a state-changing boundary
are established. The audit report schema and workflow remain unchanged because this artifact is a
derived external-agent view; its own schema begins at v1. Review-rule pack v2 adds exact scanner
rule and bounded evidence-text applicability filters, allowing embedded messaging and frame-policy
guidance to attach only to relevant findings instead of every generic configuration candidate.

## 2026-09-15 — additive project security-model declarations

The root declarative config may optionally name authentication methods, deployment topology, exact
trusted parent origins, trust-boundary labels, and tenant-isolation layers. These values guide
external review only; they never select probe destinations, suppress scanner candidates, or turn
deployment claims into observed facts. Config schema v1 and report schema v17 accept the optional
fields while older reports and configs remain readable: absent fields stay absent, no default
security conclusion is inferred, and generated agent context v1 preserves the declared/observed
split. A future breaking change to field meaning will require new schema versions rather than
reinterpretation of stored reports.

## 2026-09-15 — explicit bounded HTTP URL allowlist

The audit CLI accepts up to three repeated `--probe-url` arguments. It probes them sequentially
using the existing SSRF, DNS pinning, redirect, method, timeout, and output limits. A partial
failure remains partial coverage. Each successful observation is retained in optional
`httpProbes`; the original `httpProbe` field points to the first observation for older readers.
Report schema v17 can parse both shapes and older reports remain unchanged. Workflow v85 prevents
stale checkpoint/cache reuse after the new runtime behavior. Declared project origins never
automatically become probe destinations.
