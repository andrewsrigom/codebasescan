# Autonomous audit roadmap

## Outcome

Traceward must turn an authorized Node.js, TypeScript, React, or Next.js repository into:

1. a human report explaining risks, evidence, uncertainty, coverage, and progress;
2. a versioned agent contract containing a bounded, testable work queue.

The deterministic audit stays useful with AI disabled. AI may investigate ambiguity and propose
changes, but cannot overwrite scanner evidence, invent coverage, or verify its own work.

## Invariants

- Treat target files and scanner messages as untrusted data.
- Never install, import, build, test, or execute an audited repository.
- Keep observations, inferences, missing evidence, AI assessments, and human decisions distinct.
- Do not turn absent source evidence into proof that a runtime control is missing.
- Keep task IDs and finding fingerprints stable across unchanged snapshots.
- Require independent checks and a fresh audit before reporting a task resolved.
- Add vulnerable and structurally similar benign fixtures for every source rule.
- Add provider/framework behavior only after a reproducible real-project failure.

## Phase 1 — definitive agent output

Create `agent-plan.json` as the primary machine contract. Keep `remediation-plan.json` as a
compatibility alias until a later schema migration.

Each work item includes stable ID, root-cause group, priority, severity, confidence, exposure,
evidence references, rationale, expected change, uncertainties, change risk, automatic-fix
eligibility, human-authorization requirement, allowed paths, network policy, ordering, bounded
verification commands, and separate rescan/test/build/human acceptance criteria.

Publish a JSON Schema and validate every plan before disk. A task bundle contains only the selected
task and referenced evidence.

Gate: schema, determinism, path containment, command allowlist, compatibility alias, manifest, and
baseline-result tests pass.

## Phase 2 — safe project context and data map

Extend declarative JSON/JSONC configuration without executable hooks. Projects can describe roles,
public route expectations, auth, tenancy, billing, webhook, administration and upload features,
sensitive data classes, storage/external-service boundaries, safe command names for a later
authorized executor, important paths, and intentionally excluded paths.

Generate a source-derived map for sensitive reads, writes, responses, logs, URLs, browser storage,
cookies, outbound requests, and billing operations. Declared context and observed facts retain
different provenance.

Gate: malformed/excessive config fails closed; project names/layouts never become global rules;
context changes applicability and priority without hiding findings.

## Phase 3 — offline audit modes

Expose composable, versioned modes:

- `security`: auth, authorization, injection, secrets, dependencies, and browser/server boundaries;
- `saas`: tenant isolation, billing, tokens, webhook replay, roles, recovery, and audit logs;
- `accessibility-static`: JSX semantics, labels, keyboard use, focus, language, alternatives, ARIA;
- `privacy`: collection, client storage, sensitive logs/URLs, deletion/export, third-party transfer;
- `reliability`: timeouts, bounded retries, idempotency, failures, resource cleanup;
- `next-react`: routing, Server Actions, caching, RSC boundaries, and client sinks;
- `maintainability`: architecture, duplication, dead code, complexity, imported coverage;
- `release-readiness`: coverage failures, risky scripts, operational evidence, unresolved work.

Modes select fixed Traceward-owned packs and never target plugins. Runtime Playwright/axe remains a
separately authorized future mode.

Gate: every mode reports version, applicability, coverage, and retained/omitted counts. Disabled is
visibly different from zero findings.

## Phase 4 — quality and prioritization

Group symptoms into root-cause tasks. Prioritize with explainable severity, exposure, data impact,
operation type, reachability hint, detector confidence, and fix risk. Do not expose one unsupported
security score.

Per rule publish detector/version, supported frameworks, limitations, defensible CWE/OWASP/ASVS or
WCAG mappings, fixture TP/FP/FN, real-project dispositions, projects tested, calibration version,
and suppression/downgrade rationale. Dependency review also separates license candidates,
abandonment signals backed by captured metadata, duplicate versions, scope, and parent paths.

Gate: priority is reproducible, grouping loses no source finding, and standards mapping makes no
compliance or exploitability claim.

## Phase 5 — real-project evaluation corpus

Use authorized repositories with different structures. Start with `seusaas`, `robs-web`,
`capta-core`, `fengsoft-commerce`, and `severyn` when their roots are available. Profile before
choosing applicable modes; never infer architecture from a project name.

For each run retain an anonymized record: size, duration, memory, coverage, failures, truncation,
findings by source/rule/priority/confidence/root cause, checklist/data-map coverage, human TP/FP/
unknown/accepted/fixed decisions when available, manual misses, duplicate rate, review time, and
before/after changes.

Raw private source and secrets stay outside this repository. Generic fixtures may be derived only
after removing project-specific identifiers and sensitive content.

Gate: different projects produce useful, different results; repeated false positives are fixed or
downgraded; no broad accuracy claim relies only on synthetic fixtures.

## Phase 6 — bounded correction loop

The audit stays read-only. A separate, authorized coding-agent flow consumes one task at a time:

1. verify the candidate against source and project context;
2. record `confirmed`, `false_positive`, `inconclusive`, or `needs_human` with cited evidence;
3. change only allowed paths within configured file/line limits;
4. commit one coherent correction with its focused test;
5. run only declared and independently authorized verification commands;
6. rerun Traceward and generate a before/after result;
7. record file, command, exit status, duration, and output digest provenance.

Authentication policy, authorization policy, tenant model, database migrations, billing semantics,
destructive operations, and public deployment require human authorization. A dirty worktree,
command outside the allowlist, unexpected file expansion, failed focused test, or new critical
finding stops automatic correction.

Gate: a `seusaas` correction pass produces small commits, command provenance, fresh audit evidence,
and an honest remaining-work list.

## Phase 7 — human report

Lead with confirmed candidates, important unknowns, and failed/partial coverage; grouped root
causes; applicable checklist and data map; separated dependency/maintenance sections; before/after
progress; verification provenance; and links to JSON, SARIF, SBOM, agent plan, bundles, and schemas.

Keep raw detail lazy and bounded. Accessibility, mobile layout, script-free static output, and
truthful empty/error states are release gates.

## Phase 8 — optional structured AI

AI consumes only opaque evidence IDs and bounded related context. Its versioned workflows are:

1. investigate a deterministic finding;
2. investigate an applicable checklist gap;
3. synthesize a report from existing IDs only.

Results include assessment, cited IDs, controls found, missing evidence, impact, preconditions,
remediation choices, verification plan, confidence, limitations, provider/model, latency, tokens,
cost, cache state, and redaction state. Invalid citations or schema fail closed. AI never creates a
verified finding or completion state by itself.

Gate: disabled mode makes zero calls; mocks cover failures and budgets; live economical/strong/local
comparisons require explicit credential, spend, or download approval and measure accepted value.

## Phase 9 — release hardening

- clean-clone installation and package-content checks on supported platforms;
- incremental/cache behavior keyed by snapshot and scanner versions;
- abrupt-failure and resource-limit matrix for external scanners;
- CLI reference, JSON Schemas, rule-pack changelog, and correction-flow guide;
- comprehensive UI and static-report accessibility pass;
- name/trademark review, private vulnerability route, and support policy.

Docker, CI integrations, Kubernetes, Terraform, hosted teams, billing, and public deployment stay
outside this roadmap until local package and evidence-quality gates are complete.

## Execution order

1. Agent output and schema.
2. Project context and data map.
3. Offline modes and paired rules.
4. Root-cause grouping, prioritization, and rule-quality metadata.
5. Corpus audits and calibration.
6. Authorized `seusaas` correction loop.
7. Human report refinement.
8. Optional AI validation.
9. Release hardening.

Every phase ends with formatting, typecheck, lint, unit tests, graph tests, benchmark, build, package
test, and relevant browser tests. Commit each independently reviewable behavior change.
