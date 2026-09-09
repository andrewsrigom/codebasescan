# Roadmap

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

## Next — independent real-project ground truth

Repeat evaluation on owner-authorized applications with production context and independent human review. Record durable dispositions, manually discovered false negatives, duplicate rate, time to first useful result, coverage, and later AI cost per accepted finding. Do not publish generic accuracy claims from fixtures or the initial public source pass.

Extend structural analysis only from observed real-project failures: more ORM/query-builder shapes, nested wrapper composition, custom `tsconfig` aliases, streaming parsers, cookie overloads, and framework-specific guards. Keep unsupported relationships explicit.

Extend lockfile fidelity only from real monorepo failures and add broader stale/withdrawn advisory fixtures. Current reachability is an explicit source-reference hint, not proof that vulnerable code executes.

## Next — operational hardening

Expand fault injection beyond the tested worker `SIGKILL`, budget reservation, and checkpoint/config mismatch paths. Add deeper AI-cache migration validation and OS resource containment guidance for hostile repositories.

## Next — model validation

Run one economical and one explicitly configured stronger OpenAI model plus one local Ollama model against the same scanner evidence and adversarial repository text. Record invalid citations, abstentions, latency, tokens, configured-price cost, and whether a stronger model materially improves contextual triage. Add opt-in checklist-gap investigation only if finding investigation demonstrates measurable review value. Do not create a generic model benchmark.

## Public release

The README now uses a verified runtime screenshot and the repository includes Apache-2.0, contribution/security policies, issue templates, CI, and dependency updates.

Before publishing: record a short demo, run a fresh comprehensive accessibility audit, verify the Traceward name/trademark, test a clean clone, choose any native-platform support, and enable a private vulnerability-reporting route. Publish CI status only from a real public workflow.

## Deliberately later

Trivy, IaC/cloud IAM, dependency reachability, a human-approved patch proposal flow, broader DAST, MCP, generic RAG, multi-agent supervisors, cloud teams, billing, RBAC, compliance frameworks, and exploitation require separate product/security justification.
