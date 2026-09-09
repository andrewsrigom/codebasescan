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
- local audit comparison;
- non-interactive CI with JSON/SARIF/Markdown/HTML and severity exit gates;
- Next.js UI, worker, SQLite queue, LangGraph checkpoints, review interrupt/resume, and exports.

Code and UI remain English. Scanner evidence, runtime evidence, advisory presence, model assessment, and human disposition are separate.

## Validated environment

Primary environment: WSL2 Ubuntu 24.04.4, Node 24.19.0, npm 11.17.0. Semgrep 1.176.1 and Gitleaks 8.30.1 are installed outside the repository. OSV live lookup was exercised with the inert lodash 4.17.20 fixture. OpenAI is mocked only because no API key was available. Ollama is not installed.

See `docs/VALIDATION.md` for commands and exact counts. Do not repeat scanner installation unless version checks fail.

The ordered implementation and validation plan is in `docs/CODE_FIRST_AI_PLAN.md`.

## Next work, in priority order

1. Add AST-aware TypeScript analysis for authentication/authorization and middleware composition. Keep regex findings as candidates and add real framework counterexamples.
2. Validate one real OpenAI model and one local Ollama model on the prompt-injection suite. Record model IDs, latency, tokens, cost, invalid citations, and abstention behavior.
3. Harden storage migration and schema-validate reports and AI cache loaded from disk. The bounded OSV cache is schema-validated.
4. Add fault injection for SIGKILL/power-loss staging cleanup, worker restart, budget reservation, and checkpoint upgrade behavior.
5. Add append-only report revisions before claiming immutable audit history.
6. Expand lockfile workspaces, OSV pagination, severity parsing, and advisory freshness presentation. Do not infer dependency reachability.
7. Split the large workspace component into cohesive tab components and complete a fresh accessibility/visual regression pass.
8. Validate native macOS/Windows only if those platforms will be supported; WSL2 remains the tested path.
9. Capture real runtime screenshots, verify name/trademark availability, publish a private vulnerability-reporting route, and review dependency/API licenses before a public release.

## Guardrails

- Never execute or install the audited repository.
- Never add arbitrary shell/model/network tools to repository-driven AI.
- Never silently suppress a deterministic finding or turn missing coverage into success.
- Keep OSV and cloud AI opt-in and record what left the machine.
- Keep the HTTP probe single-target, bounded, non-destructive, and explicitly approved.
- Do not expand into generic RAG, MCP, multi-agent, billing, compliance, or SaaS team features.

## Suggested next prompt

> Read AGENTS.md, docs/ARCHITECTURE.md, docs/VALIDATION.md, and docs/CODEX_HANDOFF.md. Preserve the local-first evidence model. Implement the first remaining item only: a narrow AST-aware TypeScript authorization analyzer with vulnerable and benign Next.js fixtures. Do not weaken snapshot/path/process/network/model boundaries or add new product scope. Run and report the full validation suite.
