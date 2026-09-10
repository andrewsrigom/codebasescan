# Changelog

Notable changes are recorded here. Traceward has not published a stable release yet.

## 0.2.0 — unreleased

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
- Added an installable compiled `traceward` command whose default audit output is a self-contained static report directory.
- Added versioned remediation plans, a human task queue, baseline before/after results, and focused per-task bundles for bounded Codex handoff.
- Added bounded pnpm importer/snapshot parent paths to dependency inventory, remediation plans, HTML, Markdown, and the local workspace.
- Added safe declarative SaaS vocabulary/wrapper configuration and a dedicated LangGraph scanner node with nine focused source rules.
- Added SaaS checklist controls for tenant scope, abuse rate limiting, webhook replay, CSRF, billing, recovery, and OAuth uncertainty.
- Added explicit Next.js posture candidates for wildcard Server Action origins and broad/insecure remote image policy.
