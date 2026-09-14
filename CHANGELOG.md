# Changelog

Notable changes are recorded here.

## Unreleased

- Defined a measurable v1 offline acceptance contract for result quality, report usefulness,
  safety, portability, performance, and release integrity.
- Distinguished boolean comparisons and host/port listener endpoints from raw sensitive values in
  static logging review.
- Proved fixed-message custom error classes and static call-site error allowlists before suppressing
  internal-error response candidates.
- Retained request-derived taint through `Object.assign` option composition so nested outbound URLs
  remain visible across mapped call boundaries.
- Added API Gateway Lambda entry-point profiling and DynamoDB document-command facts so
  unauthenticated serverless mutations participate in structural review.
- Added direct and bounded cross-file SSRF detection for Node `http`/`https` `.get()` and
  `.request()` clients.
- Mapped ordered Express/Hono path middleware and explicit request-token guards into structural
  authentication evidence without applying late middleware to earlier routes.
- Recognized constant-time shared-secret and explicit token checks as webhook verification evidence
  when they occur before structured body parsing.
- Treated explicit error-code mapper results as diagnostic metadata while still inspecting their
  arguments for raw sensitive values.
- Prevented regular-expression `.exec()` calls from being classified as operating-system process
  execution sinks.
- Stopped treating caught-error values used only in response predicates as exposed response data.
- Recognized custom field wrappers with matching `label`, `htmlFor`, and nested control `id`
  evidence to reduce accessibility false positives without trusting mismatched wrappers.
- Reduced sensitive-logging noise by treating aggregate collection counts as metadata while retaining
  candidates for raw credential and personal-data values.
- Prioritized application source ahead of documentation and generated metadata in bounded snapshots,
  and excluded generated Drizzle metadata while retaining authored migrations.
- Made terminal policy output distinguish all detected candidates from the findings that gate CI.
- Updated the public demo, fixture provenance, and reusable Action smoke test to the published 0.3.0
  release.

## 0.3.0 — 2026-09-12

- Added a reusable GitHub Action that scans full repository context, builds an optional baseline
  from a Git ref, uploads the portable HTML report and SARIF, then propagates deterministic policy
  exit codes.
- Completed reviewer labels for 54 candidates across four authorized snapshots, with 95.1% sample
  precision and explicit incomplete false-negative scope rather than a recall claim.
- Added configured-webhook SSRF review and refined caught-error alias propagation using paired real
  examples, while retaining two documented broad-rule false positives instead of unsafe
  project-specific exceptions.
- Recognized common JSX `Label` components with matching `htmlFor`/`id` references as static
  accessible-name evidence.
- Limited inbound webhook signature-order findings to POST or method-unknown handlers so webhook
  configuration endpoints are not mistaken for provider callbacks.
- Kept middleware data operations separate from route operations so a shared Next.js proxy can
  contribute authentication evidence without fabricating database findings for every matched route.
- Reduced environment-contract noise by excluding writes and recognized optional/default reads
  from findings while retaining them in machine-readable coverage. Sanitized templates now preserve
  commented `NAME=` placeholders without retaining comments or values.
- Removed built-in model orchestration and its LangChain/LangGraph dependencies. CodebaseScan now
  keeps its audit engine deterministic and exports versioned contracts for separately authorized
  coding agents.
- Changed the default static output to one current coverage-style report that is safely updated in
  place. Legacy history roots remain readable, but new runs no longer accumulate audit directories.
- Added versioned real-project calibration ledgers, manual miss tracking, anonymized aggregate
  metrics, JSON Schemas, and CLI review/evaluation commands.
- Added human review guidance for every finding in the static report and React workspace, with
  evidence observations first and source/provenance details collapsed.
- Reduced real-project noise by suppressing generic ID-lookup hotspots when the structural scanner
  covered the file and by distinguishing database reads from state-changing Next.js operations.
- Added bounded inspection of forms returned by the explicitly approved HTTP probe without crawling
  or submitting them.
- Expanded the bounded snapshot to 4,000 files, 32 MiB total, and 2 MiB per source file; excluded
  conventional generated/Pagefind output and kept complete immutable reports readable up to 64 MiB.
- Reduced source-only noise by parsing comments reliably after template literals, recognizing
  payload-scoped and Server Action validation, distinguishing visual design tokens, and trusting
  navigation derived from the current pathname.
- Compacted project profiles to resolved local call edges, mapped conventional workspace build
  entrypoints back to captured TypeScript source, and invalidated every dependent scanner cache
  when the profile version changes.
- Centralized the current report schema version so portable review and suppression imports cannot
  downgrade newer reports.
- Added bounded direct and transitive dependency paths for npm lockfiles and Yarn Classic/Berry,
  including hoisted, nested, and repeated workspace declarations.
- Added declared dynamic-execution ground truth and a synchronization test so per-rule fixture
  metrics cannot drift from the benchmark corpus.

## 0.2.1 — 2026-09-11

- Added `codebasescan --version`, `codebasescan -v`, and `codebasescan version`, including packed-package smoke coverage.
- Fixed the release dry-run for versions already present on npm by requiring an exact registry integrity match.

## 0.2.0 — 2026-09-11

- Added a stable script-free `codebasescan-report/index.html` and versioned
  `report-index.json` that point to the newest immutable audit and retain bounded history.
- Added CLI help, `init`, JSON configuration schema, non-interactive CI behavior, phase timing,
  concise errors, and report-history reopening.
- Added the ninth `web-posture` mode for React/Next.js roots, monorepos, Next.js route groups,
  robots, sitemap, metadata, and optional llms.txt evidence.
- Expanded paired static accessibility coverage and added bounded import of externally generated
  Axe JSON without executing the target application or retaining selectors/raw HTML.
- Added real packed-package install tests for npm, pnpm, and Yarn, with Node 22.16 and Node 24 CI
  coverage.
- Added an npm publish dry-run regression gate that preserves the installed `codebasescan` command.
- Pinned release workflow dependencies and added a manual GitHub release dry-run that cannot publish.
- Kept Next.js/shadcn UI dependencies out of the default CLI install and made SQLite/Ollama
  integrations optional peers.
- Replaced the one-shot CLI's in-memory SQLite database with a dedicated ephemeral store, removing
  Node 22's experimental SQLite warning while preserving LangGraph memory checkpoints and AI budgets.
- Added npm public-access/provenance metadata while retaining the pre-publication `private` guard.
- Calibrated the current source-only build on `seusaas-platform`, `robs-web`, `capta-core`,
  `fengsoft-commerce`, and `severyn`, preserving unsupported and partial coverage instead of
  treating zero findings as a clean verdict.
- Added framework-aware project mapping, code-first security rules, and a versioned control checklist.
- Added bounded LangGraph investigation with optional Ollama/OpenAI providers and manual Codex bundles.
- Added persistent local audits, human review, comparison, CI gates, and JSON, Markdown, HTML, SARIF exports.
- Added Semgrep, Gitleaks, OSV, and approved single-URL HTTP integrations.
- Added decision-first report summaries, explicit coverage gaps, and real-project source evaluation.
- Ignored common generated Next.js, pnpm, Storybook, and test-output trees, raised the bounded source-file limit to 512 KiB, and allowed Semgrep more time per large source file for real monorepos.
- Applied root `.gitignore` rules during bounded scope estimation and snapshot capture so local caches and reports do not crowd out source code.
- Added a dedicated React security graph node for dynamic HTML, client-controlled URLs, browser token storage, cross-origin messaging, new-tab links, async Client Components, and server/client data boundaries.
- Split App Router methods into distinct entry points, mapped applicable middleware authentication, followed calls through five explicit hops, and attached the call path as evidence.
- Added dedicated Next.js rules for sensitive reads, tenant/owner scope, mutation validation, user-specific caching, public secret-shaped configuration, shared authenticated caching, and sensitive response fields.
- Added offline exact-version advisory matching, manual OSV database refresh, dependency source-reference hints, and CycloneDX 1.6 SBOM export.
- Expanded the passive HTTP probe with reflected-origin CORS, cache isolation, script CSP, HTTPS downgrade, retained redirect-chain, and no-cookie-value checks.
- Added explicit Git-history secret scanning, safe historical metadata, and separate probable versus test/example fixture classifications.
- Added detector confidence, probable exposure, explainable priority scores, evidence-preserving deduplication, expiring project exceptions, and explicit project baselines.
- Added vulnerable and benign benchmark projects for every dedicated Next.js and React rule, with separate precision and recall gates.
- AI-disabled audits now skip the contextual investigation subgraph entirely; workflow v2 prevents incompatible checkpoint reuse.
- Added priority, confidence, and exposure filters plus a reviewed `fixed` disposition that no longer blocks CI.
- Added a read-only-oriented `doctor` command for runtime, storage, scanner, advisory database, and AI-mode diagnostics.
- Reduced React navigation noise found in real projects by separating browser-controlled inputs from ordinary component props and restricting navigation sinks to real browser/router APIs.
- Stopped classifying arbitrary object and regular-expression `.exec()` calls as operating-system command execution.
- Lowered only the review priority, not severity, for transitive advisories with unknown source reachability so direct and referenced packages surface first.
- Added pinned offline dependency structure and duplicate-code analysis with bounded report data, route-level control visibility, and a dedicated Mechanical workspace.
- Expanded trusted local Semgrep rules for JWT, TLS, Node VM, MongoDB, error response, sensitive logging, unserialization, and URL credential review.
- Added offline Node.js supply-chain checks for lifecycle scripts, dependency sources, registry/integrity metadata, and manifest-lock consistency.
- Added isolated pinned Knip analysis, TypeScript quality hotspots, and bounded import of existing coverage summaries.
- Added selected five-hop taint propagation and source rules for command injection, path traversal, NoSQL, unsafe deserialization, dynamic regex, prototype pollution, weak digests, and mass assignment.
- Added tRPC procedure mapping and detection for Drizzle, Auth.js, GraphQL, Zod, Joi, and Valibot.
- Added safe declarative Knip settings, workspace manifests, package-script entry hints, and TypeScript path aliases to reduce monorepo dead-code noise without executing target configuration.
- Preserved exact totals for bounded architecture, quality, dead-code, and duplicate reports, and added safe file/line Semgrep parser diagnostics.
- Reduced real-project React/Next/AST/Semgrep noise by respecting nested Client Components, descriptive security wrappers, scoped service helpers, explicit public submission routes, standards-compliant `noreferrer` links, and actual logger call shapes.
- Grouped OSV findings into package/version remediation plans with conservative same-major fixed-event coverage in the workspace, Markdown, HTML, and Codex bundle exports.
- Corrected modern pnpm scoped-package parsing so packages such as `@aws-crypto/crc32` retain their full identity and advisory coverage.
- Added an installable compiled `codebasescan` command whose default audit output is a self-contained static report directory.
- Added versioned remediation plans, a human task queue, baseline before/after results, and focused per-task bundles for bounded Codex handoff.
- Added bounded pnpm importer/snapshot parent paths to dependency inventory, remediation plans, HTML, Markdown, and the local workspace.
- Added safe declarative SaaS vocabulary/wrapper configuration and a dedicated LangGraph scanner node with nine focused source rules.
- Added SaaS checklist controls for tenant scope, abuse rate limiting, webhook replay, CSRF, billing, recovery, and OAuth uncertainty.
- Added explicit Next.js posture candidates for wildcard Server Action origins and broad/insecure remote image policy.
- Added bounded resolution for captured workspace package exports and imported reexport bridges in the project graph.
- Replaced the multi-megabyte browser graph payload with a compact project-map projection.
- Added an exact-host local relay boundary for WSL while retaining browser-facing loopback checks.
- Added portable, schema-validated suppression ledgers with exact evidence targets, ownership, justification, expiry, stale-entry detection, and policy/report integration.
- Added bounded deterministic scanner caching with exact snapshot and scanner/workflow version keys, explicit hit/miss provenance, and fresh runtime/advisory/external scans.
