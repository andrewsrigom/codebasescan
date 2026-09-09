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
