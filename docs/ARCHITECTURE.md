# Architecture

## Process and trust boundaries

```text
CLI / CI ------------------------+
                                 |
loopback Next.js UI -> SQLite -> worker
                                 |
                    deterministic audit pipeline
                                 |
                    bounded read-only snapshot
                                 |
        +------------------------+------------------------+
        |                        |                        |
 built-in TypeScript rules   bundled mechanics   optional trusted tools
 AST / SaaS / Next / React   deps / duplication  Semgrep / Gitleaks
 accessibility / privacy     dead code / quality offline OSV / HTTP probe
        +------------------------+------------------------+
                                 |
                    normalize + correlate evidence
                                 |
                    current static report package
                                 |
           human review or separately authorized agent
```

The installable CLI is the primary product path. It runs the same deterministic pipeline with an
ephemeral store and writes one portable, script-free report directory. The optional repository UI
uses Node `node:sqlite`; Next.js never owns a long-running audit, and a separate worker claims
persisted jobs and handles cancellation independently of the browser.

Target source is always untrusted input. CodebaseScan reads it as bounded data, never imports target
configuration modules, and never runs target packages, lifecycle scripts, builds, tests, or
application code. Reports and stored options are runtime-schema validated on write and read.

## Audit graph

```text
START -> snapshot
              +-> project profile +
              +-> AST security -----+
              +-> SaaS security ----+
              +-> Next / React -----+
              +-> accessibility ----+
              +-> privacy / reliability
              +-> release / web ----+-> normalize + reconcile
              +-> dependencies -----+          |
              +-> supply chain -----+     build contracts
              +-> quality / dead code          |
              +-> structure / duplication      |
              +-> optional scanners -----------+-> report -> END
```

The pipeline is a small TypeScript dependency graph. It validates node dependencies, executes ready
scanner nodes concurrently, and waits for every capability to report completed, partial, skipped, or
failed status before normalization. A failed or missing capability cannot become a clean result.

All nine offline modes are enabled when an audit has no explicit selection. A focused selection
keeps the same topology but short-circuits unrelated nodes before scanner execution. Those nodes
emit explicit mode-disabled runs, preventing omitted analysis from appearing clean. Scanner cache
keys include the snapshot, scanner version, and selected variant.

Repository text cannot select tools, endpoints, headers, request bodies, commands, or local paths.
External agent review is downstream of the completed report and cannot alter scanner truth.

The UI receives a compact project-map projection instead of the full symbol/import/call graph. An
optional exact `CODEBASESCAN_INTERNAL_HOST` supports a local OS relay; browser-facing Host and Origin
checks remain restricted to loopback.

## Deterministic evidence

`project-profile.ts` parses captured TypeScript/JavaScript as data and maps Next.js, Express/Hono routes and ordered path middleware, API Gateway Lambda handlers, tRPC, Prisma, Drizzle, DynamoDB document commands, Supabase, Auth.js, GraphQL, Zod, Joi, Valibot, and billing signals plus entry points, symbols, imports, direct local call edges, and security facts under fixed limits. Same-file Express/Hono middleware applies only to later matching routes. It resolves bounded TypeScript path aliases and contained workspace package exports from declarative JSON/JSONC without loading the target compiler or package. Imported workspace reexport bridges are followed for at most five steps. A root `codebasescan.config.json`/JSONC may extend fixed tenant/owner/role/billing/token vocabulary, security helper names, and constrained public-route patterns. It cannot add code, regex, scanner plugins, suppressions, or arbitrary paths; executable CodebaseScan configuration is ignored.

The same declarative file may record bounded application features, roles, sensitive-data classes,
named storage/external boundaries, review-priority paths, report-only out-of-scope paths, and package
script names for a separately authorized correction executor. Script names are kept only when the
root manifest declares them. They are never executed by the audit. The profiler derives a separate
bounded data map from observed source facts and never treats declared context as observed flow.
Every parsed function symbol retains its exact AST line range. After findings are normalized, the
risk-correlation layer can therefore connect a finding to a reachable symbol, resolved call path,
and sensitive-operation fact without guessing from filenames. The report also preserves eligible
findings that could not be correlated and states that a static path is not runtime exploitability.

`ast-security.ts` uses profile relationships for authentication, permission, and tenant/owner scope. It performs bounded local and selected five-hop request-flow checks for SQL/NoSQL, SSRF through Fetch-style and Node HTTP clients, redirects, process execution, filesystem paths, unsafe deserialization, dynamic regular expressions, property writes, mass assignment, uploads, webhook ordering, cookie attributes, and client/server configuration. `saas-security.ts` adds focused source-to-sink rules for billing trust, ownership/privilege assignment, token entropy/lifecycle, error responses, sensitive logs/URLs, and OAuth redirects. `next-security.ts` and `react-security.ts` add framework-specific route, caching, response, client-navigation, browser-storage, messaging, rendering, and server/client-boundary rules. Target executable configuration, plugins, types, and dependencies are never loaded or executed.

`accessibility-static.ts` checks bounded JSX semantics and can import a root Axe JSON result that
was produced by an external authorized browser run. It retains violation summaries while dropping
selectors and HTML fragments; when the artifact is absent, runtime accessibility remains
`NOT PERFORMED`. `web-posture.ts` identifies root Next.js and React entries, including monorepo
packages and Next.js route groups, then correlates static robots, sitemap, metadata, and optional
llms.txt evidence. It does not infer deployment or search-engine behavior.

`supply-chain.ts` parses package manifests and npm/pnpm/Yarn lockfiles as data. It reports high-risk lifecycle declarations, plaintext or unpinned dependency sources, missing/weak integrity, non-default registry hosts, and npm manifest/lock drift. Private registries and intentional local sources remain review candidates rather than automatic compromise claims.

`quality.ts` measures function complexity, size, and parameter count through the CodebaseScan-owned TypeScript parser. Knip runs from a pinned local entry point in a temporary snapshot containing captured source, script-free sanitized workspace manifests, and a generated JSON configuration that disables every target plugin/config loader. Safe Knip JSON/JSONC exclusions, TypeScript aliases, workspace declarations, conventional configuration entry points, and source paths referenced by package scripts are imported only as bounded data. Test references participate in Knip reachability but remain excluded from production security rules. Only bounded paths and symbols are retained, while exact category totals remain visible when detail rows reach a limit. Existing `coverage-summary.json` and `lcov.info` aggregates can be imported; CodebaseScan does not run target tests.

`mechanical.ts` stages runtime JavaScript/TypeScript only and invokes pinned dependency-cruiser and jscpd entry points with fixed arguments. It does not load target tool configuration. Reports retain exact aggregate totals plus bounded cycles, orphan candidates, coupling hotspots, and duplicate locations. Raw duplicate fragments are discarded. Semgrep parser diagnostics likewise retain only a validated snapshot path, optional line, and diagnostic kind. These observations never become security findings automatically.

`builtin.ts` retains small broad review patterns when structural analysis cannot decide. `posture.ts` adds conservative TypeScript/Node/Next checks for declared browser policies, sensitive cookies, CORS, environment use, wildcard Server Action origins, and broad/insecure remote image policy. A decisive AST candidate replaces the same-location broad raw-SQL/cookie pattern to reduce duplicates. Every automatic control result is also mapped into a versioned checklist; missing runtime or infrastructure evidence remains unverified.

Snapshot files are classified as runtime, test, or example. Project profiling, AST, posture, dependency inventory, and Semgrep use runtime scope; Gitleaks retains all captured scopes because credentials in test/fixture code can still be exposed. Application source directories are prioritized ahead of documentation, agent metadata, tests, and examples during bounded traversal. Generated Drizzle journal and schema-snapshot metadata is excluded while authored SQL migrations remain available. The preflight UI reports the split before queuing. Only bounded aggregate `coverage/coverage-summary.json` and `coverage/lcov.info` files are admitted from the otherwise excluded generated coverage tree.

The HTTP probe is per audit and requires an approved URL. It accepts only HTTP(S), strips queries from stored display URLs, rejects credential-shaped query keys, blocks metadata/link-local/reserved destinations, requires explicit approval for non-loopback private networks, validates every DNS answer and redirect, and pins the selected address for the connection. It uses HEAD and only falls back to bounded GET for 405/501. Static and runtime findings are reconciled by attaching observed evidence; static evidence is not silently removed.

Lockfile inventory supports npm, pnpm, Yarn Classic, and Yarn Berry without running package-manager code and excludes recognized local npm/Yarn workspace packages from advisory queries. pnpm importer/snapshot relationships, npm package graphs, and Yarn dependency stanzas produce at most three parent paths with a fixed depth for direct and transitive remediation. npm hoisting/nesting and repeated workspace declarations are preserved; unresolved Yarn selectors omit a path instead of guessing. Exact-version records in the compact local advisory database are used without network access. Manual refresh is separately opt-in, uses the fixed OSV API host, and sends only package name/version pairs. Pagination and advisory fetches have fixed request/result limits. Full responses are compacted, aliases are consolidated, withdrawn records are ignored, package-level severity is retained, CVSS v3 vectors are scored when labels are absent, and cache/report data distinguish source-reference hints from runtime reachability or exploitability.

The terminal-first audit writes one current static, script-free report directory. Managed files are
replaced atomically, stale optional artifacts are removed from the previous manifest, and the final
manifest is written last. CodebaseScan refuses to overwrite a nonempty directory without a valid
CodebaseScan marker. The complete directory can be opened directly or hosted as static files
without a database or application server.

The remediation plan is a versioned plan-only contract. A preserved baseline audit adds a
deterministic before/after result, while the `task` command reduces that contract to one task and
its referenced evidence for bounded agent input. The `finalize` command reads existing
before/after artifacts and a strict external verification ledger. It matches exact declared
test/build commands and records bounded provenance, but never executes a project command or
authenticates the executor.

## External agent boundary

CodebaseScan has no built-in model provider or agent runtime. Static packages include
`agent-report.json`, `agent-rules.json`, `agent-plan.json`, their schemas, and a bundled Codex
skill installer. This makes deterministic output useful to the coding agent a user already trusts
without forcing a second model account, cost layer, or repository upload path.

An external agent operates under separate authorization. It must validate the report manifest,
treat repository content as untrusted data, preserve incomplete coverage, cite finding/evidence
identifiers, and keep new hypotheses or review decisions separate from deterministic findings. Code
changes and command execution require their own authorization and a fresh scan for comparison.

## Evidence, assessment, disposition, and coverage

A finding keeps detector, scanner/rule/version, original severity, file/line evidence, evidence kind,
detection time, confidence, probable exposure, review priority, optional runtime/advisory metadata,
and optional human review. Legacy report schemas can still parse earlier assessment provenance, but
new audits do not create model assessments. Human dispositions include confirmed, fixed, false
positive, accepted risk, and needs review. Expiring project exceptions keep the original finding
and exact fingerprint visible. Checklist controls separately retain deterministic status and
optional external review evidence. These states are not collapsed into “verified.”

Coverage uses explicit capability states: `COMPLETE`, `PARTIAL`, `FAILED`, `DISABLED`, `NOT RUN`, `NOT SUPPORTED`, and `NOT PERFORMED`. Zero findings and a failed scanner are therefore different results. CodebaseScan does not compute a global security score.

## Persistence

The in-process snapshot is bounded and raw content is not stored wholesale in the application
report. Findings contain small redacted excerpts and digests, which are still sensitive. Scanner
cache reuse requires an exact snapshot, scanner version, and variant.

The optional application store persists projects, audit jobs, events, validated reports, review
notes, and scanner cache data in local SQLite. A worker can recover a job abandoned by a dead local
process. Execution is not a universal exactly-once guarantee; event keys and finding fingerprints
are deterministic, and incompatible workflow versions fail closed. External parser processes still
require OS-level containment for hostile repositories.

## Local HTTP service

The CodebaseScan UI binds to `127.0.0.1`. Its own API enforces loopback Host/URL, same Origin for mutations, JSON, a UI header, and streamed body limits. This control is separate from the optional outbound target probe. The application has no multi-user authentication and must not be exposed publicly.

## Reading order

1. `src/domain/types.ts`, `checklist.ts`, `report-schema.ts`, `coverage.ts`, and `provenance.ts`
2. `src/security/paths.ts`, `url-policy.ts`, and `redact.ts`
3. `src/scanners/project-profile.ts`, `ast-security.ts`, `next-security.ts`, `react-security.ts`, `supply-chain.ts`, `quality.ts`, `mechanical.ts`, `posture.ts`, `http-probe.ts`, `inventory.ts`, and `osv.ts`
4. `src/engine/deterministic-pipeline.ts`, `audit-pipeline.ts`, and `run.ts`
5. `src/reporting/static-report.ts`, `report-server.ts`, and `src/cli/main.ts`
6. `src/server/store.ts`, `src/worker/main.ts`, and `src/components/audit-workspace.tsx`
