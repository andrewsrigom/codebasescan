# Codex handoff

## Context

Build a portfolio-quality open-source local security review tool. The owner is learning LangChain/LangGraph through a useful product, not trying to recreate a full AppSec platform in one iteration. TypeScript and Next.js are deliberate choices. UI and product wording are in English.

The existing implementation is a substantial starter with a dependency-free core that has been tested. The **first assignment is to validate and stabilize the full application**, not to start over or add unrelated infrastructure.

## P0 — Make the existing vertical slice verifiably work

1. Read `AGENTS.md`, `docs/VALIDATION.md`, `docs/THREAT_MODEL.md`, and `docs/DECISIONS.md`.
2. Use Node 22.16+ in the 22/24 lines. Run `npm install` with network access. Check the actual installed Next/React/LangGraph/checkpoint peer dependency graph. Resolve incompatible ranges deliberately and commit the resulting real `package-lock.json`. Never synthesize a lockfile.
3. Run Prettier, TypeScript, ESLint, and the core tests. Fix implementation issues rather than weakening types, guards, assertions, or rules. Dependencies were unavailable in the authoring environment; no full typecheck/build claim has been made.
4. Run `npm run test:graph`. Verify SQLiteSaver constructor/lifecycle, Annotation reducers, parallel fan-in, interrupt/resume, source-digest consistency, subgraph loop limits, and cancellation. Check actual persisted state instead of inferring successful recovery from a UI badge.
5. Run `npm run demo`, then `npm run build`. Start the UI and worker in different processes. Verify that the default demonstration contains seven review candidates, no AI claims, skipped external scanners, and manifest-only dependency inventory.
6. Install the Playwright browser and run `npm run test:e2e`. Inspect the real UI on desktop and mobile; verify keyboard access, dialog focus, findings filters, review persistence, publish resume, export downloads, malformed bodies, Host/Origin rejection, and no unexpected outbound requests.
7. With authorized inert fixtures only, manually validate the real Semgrep and Gitleaks binaries. Lock tested CLI versions in developer documentation and confirm their JSON/exit-code contracts. Then test one locally installed Ollama model, including malformed structured output and timeout. These integrations have not been exercised against real binaries/models yet.
8. Update `docs/VALIDATION.md` with exact versions, executed commands, results, and residual gaps. Only then replace the README's validation warning with an accurate release status.

### Acceptance criteria for the first runnable release

- A fresh machine can follow the README and see a real persisted demo audit.
- A registered fixture can be queued from the UI and processed by the separate worker.
- Every candidate has source, rule, location, snapshot-bound evidence, limitations, and independent human disposition.
- A disabled or failed scanner remains visible as disabled/failed, never as a clean result.
- Publication pauses using LangGraph interrupt and resumes after a real review request.
- Model failure retains the candidate with an inconclusive assessment. No cloud fallback exists.
- Cancellation cannot resurrect a job. The full core, graph, build, and browser checks pass.
- No proprietary code, API keys, real tokens, runtime DBs, or model weights enter Git.

## P1 — Harden the foundation before detection breadth

Prioritize repeatable real-binary contracts, restart/crash tests, settings-change resume policy, raw staging cleanup after hard process termination, explicit storage migration/version checks, schema-validated persisted report loading, and symlink-race isolation. Keep external scanner versions in reports once their version commands are safely integrated.

Break the workspace into cohesive tab/panel components when adding complexity. Improve accessibility and visual regression coverage without replacing the product's information hierarchy. Add an operator-facing diagnostic channel with redacted error codes, not raw secret-bearing stderr.

A report publication is currently mutable through later human finding review; add append-only report revisions before claiming audit-grade immutable history. Same-line fingerprints are only stable within comparable snapshots; define baselines before building “resolved since last scan.”

## P2 — Add useful security coverage

Choose **one** narrow improvement: AST-aware auth-boundary candidate detection with benign middleware/RLS controls, or OSV lockfile-based matching with explicit database timestamp and offline cache policy. Do not ship both plus Trivy/MCP/multi-agent services at once. Preserve the source adapter contract and add golden JSON tests for supported tool versions.

## P3 — Public portfolio release

Complete `docs/PORTFOLIO.md`: real screenshots, a reproducible demonstration, measured narrow evaluation, documented limits, license/dependency review, and a useful README. Validate name availability and set a private vulnerability-reporting route. Do not imply independent security certification or representative detection accuracy.

## Suggested next prompt

> Read AGENTS.md and docs/CODEX_HANDOFF.md. Complete P0 first. Install and resolve the real dependencies, generate package-lock.json, and run typecheck, lint, core tests, graph integration tests, Next production build, and Playwright. Fix problems without weakening the security boundaries or replacing LangGraph with a mock. Preserve the local-first design and the distinction between scanner evidence, AI assessment, and human disposition. Report exactly which checks passed and which integrations still need validation. Do not add billing, cloud inference, auto-remediation, or new scanners yet.
