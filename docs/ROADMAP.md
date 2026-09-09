# Roadmap

## Completed — serious local audit workflow

- Real Next.js/worker/LangGraph/SQLite workflow and browser validation.
- Semgrep and Gitleaks adapters validated with installed binaries and version reporting.
- Conservative TypeScript/Node/Next posture rules with paired vulnerable/benign fixtures.
- Approved single-URL HTTP posture probe with SSRF, metadata, redirect, method, timeout, and size controls.
- npm/pnpm/Yarn resolved dependency inventory and opt-in cached OSV matching.
- Explicit coverage, provenance, OpenAI Responses API adapter, cloud redaction, prompt-injection controls, benchmark, audit comparison, and CI mode.
- Deterministic TypeScript/JavaScript project profiling, framework-aware AST auth/authz, bounded direct request flows, and paired benign fixtures.
- Versioned security checklist, evidence-ID context broker, structured AI investigation, Project Map/Investigations UI, and bounded Codex bundle.
- Runtime-validated report persistence, append-only revisions, and anonymized human-outcome/AI-cost aggregation.
- Runtime/test/example source separation, pre-audit scope estimates, explicit partial-snapshot approval, baseline-aware CI artifacts, and scanner compatibility warnings.
- Actual dead-worker `SIGKILL` recovery, checkpoint/config compatibility guards, and persisted AI request reservations.
- Bounded OSV pagination, CVSS v3 scoring, package-specific severity, advisory modification display, and local npm/Yarn workspace-package exclusion.

## Next — real-project detection quality

Evaluate at least 10 authorized TypeScript/Next.js projects with human review. Record false positives, manually discovered false negatives, duplicate rate, time to first useful result, coverage, and AI cost per confirmed finding. Disable or narrow rules that fail outside fixtures. Do not publish generic accuracy claims from the fixture benchmark.

Extend structural analysis only from observed real-project failures: path aliases, wrapper composition, middleware/proxy matchers, more ORM/query-builder shapes, streaming uploads, cookie overloads, and framework-specific safe destination guards. Keep unsupported relationships explicit.

Extend lockfile fidelity only from real monorepo failures and add broader stale/withdrawn advisory fixtures. Reachability remains separate work and must not be inferred from presence.

## Next — operational hardening

Expand fault injection beyond the tested worker `SIGKILL`, budget reservation, and checkpoint/config mismatch paths. Add deeper AI-cache migration validation and OS resource containment guidance for hostile repositories.

## Next — model validation

Run one economical and one explicitly configured stronger OpenAI model plus one local Ollama model against the same scanner evidence and adversarial repository text. Record invalid citations, abstentions, latency, tokens, configured-price cost, and whether a stronger model materially improves contextual triage. Add opt-in checklist-gap investigation only if finding investigation demonstrates measurable review value. Do not create a generic model benchmark.

## Public release

Capture verified runtime screenshots and a short demo; perform accessibility, license, name/trademark, clean-install, native-platform, and private vulnerability-reporting checks. Publish CI status only from a real public workflow.

## Deliberately later

Trivy, IaC/cloud IAM, dependency reachability, a human-approved patch proposal flow, broader DAST, MCP, generic RAG, multi-agent supervisors, cloud teams, billing, RBAC, compliance frameworks, and exploitation require separate product/security justification.
