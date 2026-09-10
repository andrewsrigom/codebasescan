# Roadmap

The full execution sequence and release gates are maintained in
[Autonomous audit roadmap](AUTONOMOUS_ROADMAP.md).

## Completed — serious local audit workflow

- Real Next.js/worker/LangGraph/SQLite workflow and browser validation.
- Semgrep and Gitleaks adapters validated with installed binaries and version reporting.
- Conservative TypeScript/Node/Next posture rules with paired vulnerable/benign fixtures.
- Approved single-URL HTTP posture probe with SSRF, metadata, redirect, method, timeout, and size controls.
- npm/pnpm/Yarn resolved dependency inventory, manually refreshed offline OSV matching, source-reference reachability hints, and CycloneDX 1.6 export.
- Explicit coverage, provenance, OpenAI Responses API adapter, cloud redaction, prompt-injection controls, benchmark, audit comparison, and CI mode.
- Deterministic TypeScript/JavaScript project profiling, framework-aware AST auth/authz, bounded direct request flows, and paired benign fixtures.
- Versioned security checklist, evidence-ID context broker, structured AI investigation, Project Map/Investigations UI, and bounded Codex bundle.
- Runtime-validated report persistence, append-only revisions, and anonymized human-outcome/AI-cost aggregation.
- Runtime/test/example source separation, pre-audit scope estimates, explicit partial-snapshot approval, baseline-aware CI artifacts, and scanner compatibility warnings.
- Actual dead-worker `SIGKILL` recovery, checkpoint/config compatibility guards, and persisted AI request reservations.
- Bounded OSV pagination, CVSS v3 scoring, package-specific severity, advisory modification display, and local npm/Yarn workspace-package exclusion.
- Initial ten-project source-only evaluation: 1,010 files, complete profiles, lockfile/alias/entrypoint/upload hardening, and documented manual triage without a broad accuracy claim.
- Dedicated React client-boundary rules cover dynamic HTML, navigation, Web Storage, postMessage, new-tab isolation, async Client Components, and sensitive server-to-client props.
- Dedicated Next.js rules cover sensitive reads, tenant/owner scope, mutation validation, user-specific caching, public secret-shaped configuration, shared authenticated caching, and sensitive response fields.
- The approved passive HTTP probe now covers effective headers, CSP, CORS reflection and variation, sensitive cookie metadata, shared caching, and redirect downgrades without crawling or mutation.
- Secret scanning distinguishes probable runtime matches from test/example fixture candidates and supports an explicit, redacted Git-history mode.
- Findings now carry detector confidence, probable exposure, priority scores, merged evidence, expiring project exceptions, and a selectable project baseline.
- Every dedicated Next.js and React rule now has declared vulnerable ground truth plus paired benign benchmark coverage.
- The local environment doctor, fixed disposition, quality filters, and owner-authorized 1,000+ file scale pass are complete.
- Pinned offline dependency-cruiser and jscpd adapters now add bounded cycles, coupling hotspots, orphan candidates, and duplicate locations without loading target configuration or retaining raw duplicate fragments.
- The project map now shows observed authentication, authorization, validation, and sensitive-operation evidence for each mapped request boundary.
- Local Semgrep coverage now includes JWT verification gaps, Node VM execution, disabled TLS verification, MongoDB `$where`, error-stack responses, sensitive logging, unsafe unserialization, and credentials in URL parameters.
- Node.js supply-chain review now covers high-risk lifecycle scripts, unsafe/unpinned sources, lockfile URLs and integrity, registry hosts, and npm manifest/lock drift without installing packages.
- Pinned Knip analysis runs against a script-free sanitized manifest with every target plugin disabled; reports retain bounded unused-file, dependency, export, and type candidates.
- TypeScript quality metrics now retain function complexity, size, and parameter hotspots and import only bounded existing coverage aggregates.
- Bounded architecture, quality, dead-code, and duplication reports now preserve exact totals alongside retained detail counts; Semgrep parser diagnostics expose only safe snapshot file/line locations.
- Structural source review now recognizes tRPC procedures and common Node/React/Next data/auth/validation libraries, follows selected tainted arguments across five explicit calls, and covers command/path/NoSQL/deserialization/regex/prototype/mass-assignment candidates.
- Safe declarative project ingestion now applies Knip JSON/JSONC exclusions, npm/pnpm workspaces, package-script entry hints, and TypeScript path aliases without executing target configuration. Test references participate only in maintenance reachability.
- The 1,196-file `seusaas-platform` pressure test now calibrates nested React client boundaries, descriptive auth/validation wrappers, scoped service helpers, public submission routes, new-tab protection, and structured-log matching; 45 reproducible false positives were removed while benchmark recall stayed unchanged.
- Dependency findings now collapse into actionable package/version plans with conservative OSV fix coverage, lazy full-inventory rendering, and matching Markdown, HTML, and Codex bundle exports. Modern pnpm scoped packages retain their complete names.
- The installable terminal command now generates self-contained static report directories with human HTML, audit JSON, prioritized remediation tasks, bounded Codex evidence, SARIF, CycloneDX, and artifact hashes by default.
- Baseline runs now emit deterministic before/after remediation results, and focused task bundles let an authorized agent consume one work item without sending the complete report.
- pnpm dependency inventory now retains bounded lockfile parent paths, so direct owners are visible for transitive remediation without loading project configuration.
- Generic declarative SaaS semantics now support bounded tenant/owner/role/billing/token vocabulary, security wrapper aliases, and constrained public routes without executable project configuration.
- A dedicated SaaS graph node now reviews client-controlled billing, ownership/privilege assignment, token entropy/storage/expiry, internal error responses, sensitive logs/URLs, and OAuth redirect trust with paired vulnerable and benign benchmarks.
- The checklist now exposes mechanical SaaS controls for tenant scope, rate limiting, webhook replay, CSRF, billing trust, recovery-token lifecycle, and OAuth uncertainty without converting missing evidence into a confirmed vulnerability.
- Next.js posture review now flags explicit wildcard Server Action origins and broad or insecure remote image declarations.
- Captured workspace package exports and imported reexport bridges now participate in the bounded project graph without loading package code or build configuration.

## Next — independent real-project ground truth

Repeat evaluation on owner-authorized applications with production context and independent human review. Record durable dispositions, manually discovered false negatives, duplicate rate, time to first useful result, coverage, and later AI cost per accepted finding. Do not publish generic accuracy claims from fixtures or the initial public source pass.

Extend structural analysis only from observed real-project failures: more ORM/query-builder shapes, nested wrapper composition, streaming parsers, cookie overloads, and framework-specific guards. Keep unsupported relationships explicit.

Continue calibrating the generic SaaS pack on structurally different owner-authorized applications. The initial `seusaas-platform` and `robs-web` runs establish pressure and portability checks, not owner-confirmed ground truth. Add new provider/ORM adapters only after recording missed source shapes or reproducible false positives; do not encode one reference project's names or directory layout into rules.

Extend npm/Yarn parent-path fidelity only from real monorepo failures and add broader stale/withdrawn advisory fixtures. Current reachability is an explicit source-reference hint, not proof that vulnerable code executes.

## Next — operational hardening

Expand fault injection beyond the tested worker `SIGKILL`, budget reservation, and checkpoint/config mismatch paths. Add deeper AI-cache migration validation and OS resource containment guidance for hostile repositories.

## Next — model validation

Run one economical and one explicitly configured stronger OpenAI model plus one local Ollama model against the same scanner evidence and adversarial repository text. Record invalid citations, abstentions, latency, tokens, configured-price cost, and whether a stronger model materially improves contextual triage. Add opt-in checklist-gap investigation only if finding investigation demonstrates measurable review value. Do not create a generic model benchmark.

## Public release

The README now uses a verified runtime screenshot and the repository includes Apache-2.0, contribution/security policies, issue templates, CI, and dependency updates.

Before publishing: record a short demo, run a fresh comprehensive accessibility audit, verify the Traceward name/trademark, test a clean clone, choose any native-platform support, and enable a private vulnerability-reporting route. Publish CI status only from a real public workflow.

## Deliberately later

Trivy, IaC/cloud IAM, dependency reachability, a human-approved patch proposal flow, broader DAST, MCP, generic RAG, multi-agent supervisors, cloud teams, billing, RBAC, compliance frameworks, and exploitation require separate product/security justification.
