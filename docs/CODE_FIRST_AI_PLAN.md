# Code-first audit and AI investigation plan

## Implementation status — 2026-09-09

- Phases 1-4 are implemented: deterministic profiler, five-hop bounded relationships, dedicated Next.js and React rules, versioned checklist, and opaque evidence-ID context broker.
- Phase 5 workflow A is implemented for Ollama/OpenAI contracts; structured results include controls, missing evidence, impact, preconditions, remediation choices, and safe tests. Disabled mode remains complete. Checklist-gap calls and AI report synthesis are intentionally deferred until real-project evidence justifies their cost.
- Phase 6 tooling is implemented through the anonymized `evaluate` command. A ten-project public source-only pass covered 1,010 files and drove lockfile, entrypoint, alias, Pages Router, upload, taint, and false-positive corrections. Owner-confirmed private-project ground truth remains future validation.
- Phase 7 includes validated append-only reports, actual worker `SIGKILL` recovery, AI budget reservation persistence, checkpoint/config compatibility guards, scanner-version warnings, baseline-aware CI artifacts, and explicit pre-audit truncation approval.
- Phase 8 includes Project Map, Checklist, Findings, Coverage, Investigations, Workflow, a bounded Codex bundle export, and human checklist assessments that survive publication without rewriting deterministic state.

The next product gate is independent human ground truth on owner-authorized applications, followed by optional live-model validation only if it improves review quality.

## Goal

Make CodebaseScan useful on real TypeScript, Node.js, and Next.js repositories when source code and configuration are the main evidence. Logs, traces, deployment access, and telemetry remain optional corroboration. Missing runtime evidence must never be reported as a clean result.

## Product position

CodebaseScan is an evidence-led audit workbench, not another generic SAST engine. It combines trusted deterministic scanners, framework-aware source analysis, explicit control checklists, bounded AI investigation, human review, coverage reporting, and reproducible exports.

The primary users are developers and reviewers auditing applications they own or are authorized to assess. The first supported stack is TypeScript/JavaScript with Next.js, common Node.js route handlers, Prisma-style data access, and Supabase-style authentication/data access.

## Non-negotiable boundaries

- Never execute, install, build, or import the audited repository.
- Parse captured source as data using CodebaseScan-owned dependencies only.
- Never follow symlinks or read excluded working-tree credentials, generated trees, or paths outside the approved root. Git history is read only by the trusted Gitleaks adapter after explicit per-audit approval.
- Repository text is untrusted input, including comments, prompts, configuration, and generated files.
- Models receive no shell, network, filesystem, package-manager, browser, or mutation tools.
- A model cannot delete a deterministic finding, lower scanner severity, mark a control complete, or publish a report.
- Findings distinguish observed evidence, declared configuration, inferred relationships, missing evidence, and human disposition.
- Disabled, failed, partial, unsupported, and not performed coverage remain visibly different.
- Network capabilities are separately opted in: OSV, HTTP posture probe, and cloud AI never authorize one another.
- Every expensive activity has file, byte, finding, request, round, token, time, and cost limits.

## Result model

Every audit produces four related outputs:

1. **Project profile** — frameworks, entry points, routes, server actions, middleware/proxy, authentication providers, data-access libraries, sensitive sinks, deployment/config files, and supported/unsupported source areas.
2. **Control checklist** — each control is `EVIDENCED`, `GAP_CANDIDATE`, `UNVERIFIED`, `NOT_APPLICABLE`, `PARTIAL`, or `FAILED`. Absence alone does not become a vulnerability.
3. **Findings** — deterministic candidates with exact evidence, provenance, original severity, limitations, remediation, and suggested verification.
4. **Investigations** — optional model context attached to a finding or checklist gap, with cited evidence IDs, missing evidence, confidence, token/cost data, cache status, and model provenance.

## Phase 1 — structural project profiler

Build a deterministic profile before running AI.

### Capabilities

- Detect TypeScript/JavaScript, Next.js App Router/Pages Router, Express-style routing, Prisma, and Supabase signals.
- Inventory route handlers, HTTP methods, dynamic route parameters, server actions, middleware/proxy matchers, and API entry points.
- Inventory authentication calls, authorization/role/ownership checks, validation calls, database operations, raw SQL, outbound requests, command execution, file access, redirects, cookies, and response construction.
- Record imports, exported functions, local call edges, and wrapper relationships without executing modules.
- Record parse failures and unsupported syntax per file; do not silently fall back to a clean profile.
- Use stable profile IDs derived from snapshot/file/symbol facts.

### Limits

- Maximum 2,000 source files, 200,000 AST nodes per file, 20,000 symbols, and 50,000 edges.
- Parse only captured text with TypeScript's parser. No typecheck against the target, executable configuration, plugins, transformers, or `tsconfig` execution.
- Cross-file analysis follows captured relative, `@/`, `~/`, root-alias, and bounded declarative `tsconfig` path imports plus exported identifiers for at most five hops. Unsupported compiler logic stays explicit.

### Exit gate

- Positive and benign fixtures for App Router routes, server actions, wrappers, proxy/middleware, Prisma, and Supabase.
- Malformed, oversized, generated, aliased, and unsupported files produce explicit partial coverage.
- Profile is persisted in schema-versioned reports and visible in JSON plus the UI.

## Phase 2 — framework-aware deterministic analysis

Use the profile and AST facts to replace the noisiest regex candidates.

### First rules

1. Mutating route or server action reaches a sensitive operation without an authentication guard.
2. Resource lookup/update uses caller-controlled ID without tenant, owner, or policy evidence.
3. Admin route reaches a sensitive operation without role/permission evidence.
4. Raw SQL contains interpolation or concatenation from request-controlled input.
5. Outbound request uses caller-controlled destination without allowlist/validation evidence.
6. Redirect uses caller-controlled destination without same-origin/allowlist evidence.
7. Upload path lacks size/type/path constraints before storage.
8. Webhook handler processes a body before signature verification.
9. Sensitive cookie lacks secure attributes in the effective options object.
10. Client-reachable module references server-only secret configuration.

### Analysis policy

- Prefer high-precision, framework-specific rules over broad pattern count.
- Every positive fixture has a structurally similar benign counterexample.
- Preserve the existing regex result when AST analysis cannot decide, but label its detector and confidence separately.
- Do not infer that middleware, RLS, database policy, API gateway policy, or deployment configuration exists when it is outside the snapshot.

### Exit gate

- No regression in current scanner tests.
- Category benchmark reports TP/FP/FN, precision, and recall for AST rules independently from legacy patterns.
- Initial AST precision target at least 0.90 and recall target at least 0.85 on declared fixtures.

## Phase 3 — security control checklist

Create versioned CodebaseScan-owned control packs. Repository content cannot define executable rules.

### Initial domains

- Authentication and session management.
- Authorization, tenant isolation, and administrative access.
- Input validation and output encoding.
- SQL/NoSQL injection and dangerous evaluation.
- Secrets and client/server environment boundaries.
- Cookies, CSRF, CORS, headers, and caching.
- SSRF, redirects, webhooks, and outbound integrations.
- Uploads, file/path handling, and command execution.
- Error handling, audit logging declarations, and sensitive logging.
- Dependencies, CI configuration, containers, and deployment configuration.
- AI tool/prompt boundaries when AI code is present in the target.

### Checklist policy

- `EVIDENCED` requires a concrete source/config fact and never means globally secure.
- `GAP_CANDIDATE` means an expected control was not found in analyzed scope.
- `UNVERIFIED` means the control may exist in runtime infrastructure, RLS, an identity provider, or another repository.
- Each item states applicability, evidence, missing evidence, verification steps, and coverage limitations.
- Checklist versions are embedded in reports for reproducibility.

### Exit gate

- Paired fixtures cover every automatic checklist transition.
- Report exports and CI expose checklist state without converting gaps into confirmed vulnerabilities.

## Phase 4 — bounded context broker

Give reviewers and optional models the smallest useful evidence bundle.

### Read-only operations

- Get an excerpt by existing evidence ID.
- Get a symbol declaration by profile symbol ID.
- Get callers/callees from recorded bounded edges.
- Get imports and directly related configuration facts.
- Get checklist facts relevant to a finding.

### Controls

- Models request opaque IDs, not arbitrary paths.
- Every request is checked against the immutable captured snapshot.
- Quick, standard, and deep modes apply fixed limits to rounds, requested items, accumulated
  context, searched snapshot characters, findings, and configured token/cost budgets.
- Standard and deep modes accept at most two sanitized plain-text searches per round and return
  opaque search-result IDs.
- Requested and delivered context is recorded in provenance.

### Exit gate

- Path traversal, secret-file, prompt-injection, excessive-context, unknown-ID, repeated-request, and budget-exhaustion tests pass.

## Phase 5 — useful AI workflows

AI remains optional. The same workflow supports disabled, local Ollama, and opt-in OpenAI providers.

### Workflow A: finding investigation

For one deterministic finding, return structured:

- assessment: `likely`, `unlikely`, or `inconclusive`;
- rationale;
- cited evidence IDs;
- controls found;
- missing evidence;
- likely impact and preconditions;
- remediation options;
- a safe verification/test plan;
- confidence and limitations.

This is the highest-priority AI workflow.

### Workflow B: checklist gap investigation

Investigate one applicable `GAP_CANDIDATE` using profile facts and bounded related context. The model may reclassify only its own assessment as likely/unlikely/inconclusive; the deterministic checklist state remains unchanged until human review.

### Workflow C: report synthesis

Generate an executive and developer summary only after findings/checklists exist. It cites report IDs, preserves failed/disabled coverage, and cannot invent new verified findings. This is lower value than A and B.

### Routing and cost

- No model call for clean or obviously redundant evidence by default.
- Use the economical configured model for normal investigation.
- Use a separately configured stronger model only for critical/high ambiguous findings or an explicitly requested second opinion.
- Cache by provider, model, prompt version, profile digest, finding/checklist fingerprint, and redacted context digest.
- Persist calls, retries, input/output tokens, configured-price estimate, cache hits, failures, and budget denials.

### Exit gate

- Disabled mode performs zero model-network calls.
- Mocked provider contract tests cover schema, citations, redaction, timeouts, retries, cache, and budgets.
- Live-provider release validation requires explicit credentials and records model ID, latency, tokens, cost, invalid citations, and abstention behavior.

## Phase 6 — real-project evaluation

Fixtures prevent regressions but do not prove usefulness.

### Evaluation set

- Start with 10 authorized, non-sensitive TypeScript/Next.js projects of different sizes and architectures.
- Record only anonymized metrics unless the owner approves retaining evidence.
- Include projects with Prisma, Supabase, custom auth, middleware wrappers, server actions, APIs, webhooks, uploads, and third-party calls.

### Measures

- Actionable findings accepted by a human reviewer.
- False positives, false negatives found by manual review, duplicate rate, and inconclusive rate.
- Time to first useful finding and total review time.
- Percentage of findings with exact evidence and usable remediation.
- Coverage by framework/control domain.
- AI token/cost per accepted finding and whether AI changed reviewer understanding.
- Findings uniquely surfaced by CodebaseScan versus raw Semgrep/Gitleaks/OSV output.

### Release gate

- Publish no broad accuracy claim from fixtures alone.
- Keep per-rule precision/recall and known failure modes visible.
- Disable or downgrade rules that repeatedly fail the quality threshold.

## Phase 7 — operational hardening

- Schema-validate persisted reports, profiles, checklist results, AI cache, and migrations.
- Add crash/power-loss tests for checkpoints and AI budget reservations.
- Add append-only report revisions and comparison by stable structural fingerprint.
- Add scanner compatibility fixtures and version warnings.
- Add SARIF/JSON artifacts and baseline-diff gates for GitHub Actions without requiring cloud AI.
- Add repository-size estimates and explicit truncation before an audit starts.

These items are implemented. Wider OS/platform fault matrices remain release validation work rather than missing workflow code.

## Phase 8 — product UX

- Add Project Map, Checklist, Findings, Coverage, Investigations, and Workflow views.
- Lead with prioritized evidence, not a numeric security score.
- Show why a control applies, what was checked, what is missing, and how to verify it.
- Provide developer remediation and safe test suggestions beside exact evidence.
- Keep raw scanner output provenance available without exposing secrets.
- Add an investigation bundle export for manual review with Codex or another authorized tool.

## Commit sequence

Use small reviewable commits, each with its own tests:

1. `docs: define code-first AI audit milestones`
2. `feat: add deterministic project profiling`
3. `feat: add bounded TypeScript AST relationships`
4. `feat: add framework-aware authorization rules`
5. `feat: add versioned security checklist results`
6. `feat: add evidence-ID context broker`
7. `feat: investigate findings with bounded AI context`
8. `feat: expose project map and checklist in reports`
9. `test: expand security benchmark and fault coverage`
10. `docs: record real-project validation and limits`

Do not combine unrelated UI, scanner, provider, and documentation changes in one commit.

## Validation after every milestone

Run:

```bash
npm run format:check
npm run typecheck
npm run lint
npm test
npm run test:graph
npm run benchmark
```

Before a release also run:

```bash
npm run build
npm run test:e2e
npm audit --audit-level=low
```

Validate Semgrep/Gitleaks real binaries, one live OSV lookup, one approved HTTP probe, disabled-mode zero network behavior, and browser console/error-overlay state. Live Ollama/OpenAI checks remain explicit opt-ins.

## Autonomous stop conditions

Continue without asking while changes are local, read-only toward audited repositories, covered by this plan, and reversible in Git. Stop and request user input only when work requires:

- real private repository paths or permission to retain their results;
- an OpenAI/API credential or permission to spend money;
- a local model download with significant disk/RAM cost;
- a public push, release, deployment, or external message;
- destructive migration of existing audit data;
- expansion beyond authorized source/config auditing.
