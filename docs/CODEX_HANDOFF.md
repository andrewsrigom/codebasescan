# Codex handoff

## Current release

Traceward now has a complete local-first audit slice:

- bounded snapshots without target execution;
- built-in and application-posture rules with positive and benign fixtures;
- real Semgrep 1.176.1 and Gitleaks 8.30.1 worker integration;
- opt-in SSRF-hardened single-URL HTTP response observation;
- npm/pnpm/Yarn resolved inventory and opt-in cached OSV matching;
- explicit capability coverage and finding provenance;
- disabled, Ollama, and opt-in OpenAI Responses API providers;
- OpenAI structured output, `store: false`, redaction, cache, timeout/retry, persisted budgets, token/cost metadata, and no fallback;
- prompt-injection fixtures and snapshot-only file access;
- category-organized benchmark with precision/recall;
- deterministic project profile with stable route/symbol/import/call/fact IDs;
- framework-aware auth/authz and direct raw-SQL, SSRF, redirect, upload, webhook, cookie, and client-secret AST candidates;
- versioned control checklist with gap/evidenced/unverified/partial/failed/not-applicable states;
- opaque evidence-ID context broker with two rounds, repeated/unknown-ID rejection, redaction, and 16,000-character cap;
- structured model impact, precondition, remediation, safe-test, missing-evidence, and control output;
- local audit comparison;
- non-interactive CI with JSON/SARIF/Markdown/HTML/bounded-Codex-bundle output and severity exit gates;
- runtime-validated reports/options, append-only workflow/human-review revisions, and anonymized evaluation aggregation;
- Next.js UI, worker, SQLite queue, LangGraph checkpoints, review interrupt/resume, and exports.

Code and UI remain English. Scanner evidence, runtime evidence, advisory presence, model assessment, and human disposition are separate.

## Validated environment

Primary environment: WSL2 Ubuntu 24.04.4, Node 24.19.0, npm 11.17.0. Semgrep 1.176.1 and Gitleaks 8.30.1 are installed outside the repository. OSV live lookup was exercised with the inert lodash 4.17.20 fixture. OpenAI is mocked only because no API key was available. Ollama is not installed.

See `docs/VALIDATION.md` for commands and exact counts. Do not repeat scanner installation unless version checks fail.

The ordered implementation and validation plan is in `docs/CODE_FIRST_AI_PLAN.md`.

## Next work, in priority order

1. Run Traceward on 10 authorized real TypeScript/Next.js repositories, review every candidate, use `npm run cli -- evaluate ...`, and record anonymized metrics. This requires repository paths and owner authorization.
2. Fix only rule/profile/checklist failures demonstrated by that evaluation: aliases, wrappers, middleware, ORM shapes, uploads, cookies, or framework guards.
3. Validate one economical and one stronger OpenAI model only with an explicit key/spend approval; validate Ollama only if local-model disk/RAM cost is accepted. Measure whether either improves human triage.
4. Add actual SIGKILL/power-loss fault injection for budget reservation and checkpoint upgrade behavior. Dead-worker requeue and narrow stale-staging cleanup are covered.
5. Expand lockfile workspaces, OSV pagination, severity parsing, and advisory freshness presentation. Do not infer dependency reachability.
6. Split the large workspace component into cohesive tab components and complete a fresh accessibility/visual regression pass.
7. Validate native macOS/Windows only if those platforms will be supported; WSL2 remains the tested path.
8. Capture real runtime screenshots, verify name/trademark availability, publish a private vulnerability-reporting route, and review dependency/API licenses before a public release.

## Guardrails

- Never execute or install the audited repository.
- Never add arbitrary shell/model/network tools to repository-driven AI.
- Never silently suppress a deterministic finding or turn missing coverage into success.
- Keep OSV and cloud AI opt-in and record what left the machine.
- Keep the HTTP probe single-target, bounded, non-destructive, and explicitly approved.
- Do not expand into generic RAG, MCP, multi-agent, billing, compliance, or SaaS team features.

## Suggested next prompt

> Read AGENTS.md, docs/ARCHITECTURE.md, docs/VALIDATION.md, docs/CODE_FIRST_AI_PLAN.md, and docs/CODEX_HANDOFF.md. Preserve the local-first evidence model. Audit only an explicitly authorized real repository. Review candidates with evidence, record dispositions, export the anonymized evaluation, and make no generic accuracy claim. Do not enable cloud AI, probe a runtime target, or modify the audited repository without separate authorization.
