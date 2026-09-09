# Roadmap

## Completed — serious local audit workflow

- Real Next.js/worker/LangGraph/SQLite workflow and browser validation.
- Semgrep and Gitleaks adapters validated with installed binaries and version reporting.
- Conservative TypeScript/Node/Next posture rules with paired vulnerable/benign fixtures.
- Approved single-URL HTTP posture probe with SSRF, metadata, redirect, method, timeout, and size controls.
- npm/pnpm/Yarn resolved dependency inventory and opt-in cached OSV matching.
- Explicit coverage, provenance, OpenAI Responses API adapter, cloud redaction, prompt-injection controls, benchmark, audit comparison, and CI mode.

## Next — detection quality

Replace the highest-value auth/authz regex candidates with narrow AST-aware analysis. Model common Next.js wrappers, middleware/proxy matchers, tenant ownership, and benign RLS/service-policy counterexamples. Measure false positives and false negatives before adding languages.

Extend lockfile workspace fidelity, OSV pagination, withdrawn/advisory freshness tests, and severity-vector presentation. Reachability remains separate work and must not be inferred from presence.

## Next — operational hardening

Add crash/fault injection, stale scanner staging cleanup, checkpoint/config version compatibility, schema-validated persisted reports/caches, append-only report revisions, and scanner-version compatibility fixtures. Add OS resource containment guidance for hostile repositories.

## Next — model validation

Run one economical and one explicitly configured stronger OpenAI model plus one local Ollama model against the same scanner evidence and adversarial repository text. Record invalid citations, abstentions, latency, tokens, configured-price cost, and whether a stronger model materially improves contextual triage. Do not create a generic model benchmark.

## Public release

Capture verified runtime screenshots and a short demo; perform accessibility, license, name/trademark, clean-install, native-platform, and private vulnerability-reporting checks. Publish CI status only from a real public workflow.

## Deliberately later

Trivy, IaC/cloud IAM, dependency reachability, a human-approved patch proposal flow, broader DAST, MCP, generic RAG, multi-agent supervisors, cloud teams, billing, RBAC, compliance frameworks, and exploitation require separate product/security justification.
