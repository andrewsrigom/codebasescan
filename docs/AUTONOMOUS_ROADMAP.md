# Autonomous audit roadmap

## Outcome

CodebaseScan must turn an authorized Node.js, TypeScript, React, or Next.js repository into:

1. a human report explaining risks, evidence, uncertainty, coverage, and progress;
2. a versioned agent contract containing a bounded, testable work queue.
3. a machine-readable coverage and policy result that distinguishes a clean check from one that
   was disabled, unsupported, truncated, skipped, or failed.

The deterministic audit stays useful with AI disabled. AI may investigate ambiguity and propose
changes, but cannot overwrite scanner evidence, invent coverage, or verify its own work.

## Implementation checkpoint — 2026-09-11

Phases 1–5, 7, and 8 are implemented for the 0.2 release boundary. Correlated evidence includes
source-risk paths, environment/OpenAPI/database/webhook/feature-flag contracts, framework-major
coverage, monorepo ownership, test references, and component-aware lifecycle comparison. Phase 6
has a reproducible five-project corpus covering `seusaas-platform`, `robs-web`, `capta-core`,
`aster-streaming-platform`, and `severyn`; a separate versioned calibration ledger, anonymized
aggregate, CLI review commands, and accuracy-claim gate are implemented. The workflow-v32 pass
captured 5,980 supported files without snapshot truncation and produced 156 candidates. Independent
dispositions and false-negative review remain. Phase 10 now includes the installable CLI, stable
static report root, npm/pnpm/Yarn clean install smoke tests, Node 22/24 CI, package dependency
separation, guarded provenance metadata, and a public security-reporting route. Native
Windows/macOS claims, signed releases, and independent ground truth remain.

Portable scoped suppressions are implemented with owner, justification, supporting evidence,
creation/expiry, and exact fingerprint/rule/path/source-digest matching. Stale, expired, and
unmatched records remain counted; reviewer identity/signature policy is still future hardening.

The versioned run manifest is implemented and publishes mode selection, snapshot limits, scanner
status/duration, explicit coverage state, limitations, and output digests with a JSON Schema.
Deterministic scanners now use a bounded local cache keyed by the exact snapshot, scanner version,
workflow version, and safe variant. Scanners that consume the structural profile also key their
cache on the profile scanner version. Runtime, advisory, Git-history, and external scanner evidence
is intentionally refreshed instead of replayed. Entries are atomically written with per-entry,
entry-count, and total-size limits.

## Invariants

- Treat target files and scanner messages as untrusted data.
- Never install, import, build, test, or execute an audited repository.
- Keep observations, inferences, missing evidence, AI assessments, and human decisions distinct.
- Do not turn absent source evidence into proof that a runtime control is missing.
- Never collapse disabled, unsupported, not-applicable, truncated, and failed analysis into zero
  findings; publish the exact reason and affected scope.
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
task and referenced evidence. Contract v5 identifies the owning workspace components and matching
security-critical test targets; bundle v3 includes the selected component boundary, neighboring
component edges, and bounded related-test references.

Publish a versioned run manifest beside the report. It records repository/snapshot identity,
CodebaseScan and pack versions, requested and effective modes, scanner status, supported/unsupported
scope, truncation, elapsed time, and output digests without copying source or secrets.

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
- `web-posture`: robots, sitemap, Next.js metadata, optional llms.txt presence, and declared web
  discovery posture.

Modes select fixed CodebaseScan-owned packs and never target plugins. Static accessibility has six
paired JSX rules. A separately authorized browser runner may supply a bounded Axe JSON artifact;
CodebaseScan imports it without launching the target application or browser.

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

Support scoped suppressions with owner, justification, evidence, creation date, optional expiry,
and exact rule/path/fingerprint targeting. Expired, stale, and overly broad suppressions remain
visible; suppression never changes scanner coverage or deletes the underlying observation.

Gate: priority is reproducible, grouping loses no source finding, and standards mapping makes no
compliance or exploitability claim.

## Phase 5 — correlated risk and contract consistency

Turn isolated observations into bounded, explainable source paths such as public entry point to
request-derived value to privileged operation to sensitive response. Correlation never invents
reachability: every edge cites an existing profile fact, call edge, or finding, and unsupported
edges remain explicit.

Add deterministic consistency checks for environment variables versus declarative examples,
route handlers versus captured OpenAPI declarations, source models versus captured schema and
migration declarations, webhook producers versus consumers, feature flags versus guarded code,
and framework security configuration versus the routes it is expected to protect. A mismatch is a
review candidate, not proof of a runtime vulnerability.

Treat monorepo applications and packages as separately owned components with explicit trust
boundaries. Add a baseline/diff mode that reports introduced, resolved, changed, and reappearing
work by component. Publish the detected framework and major-version support level for every
version-sensitive rule; unsupported versions stay unverified rather than clean.

Gate: correlated paths retain every underlying evidence ID, contract checks have paired fixtures,
component ownership never relies on directory names alone, and a changed-file audit cannot hide
unchanged high-priority work from the complete report.

Security-critical test relationships follow the documented bounded method in
[Security-critical test evidence](TEST_EVIDENCE.md). API route matching follows
[API contract consistency](API_CONTRACT.md). Database relationships follow
[Database contract consistency](DATABASE_CONTRACT.md). Webhook relationships follow
[Webhook contract correlation](WEBHOOK_CONTRACT.md). Feature flags follow
[Feature flag consistency](FEATURE_FLAGS.md). AI review and future correction must follow
[Structured AI review standard](AI_REVIEW_STANDARD.md).

## Phase 6 — real-project evaluation corpus

Use authorized repositories with different structures. Start with `seusaas`, `robs-web`,
`capta-core`, `aster-streaming-platform`, and `severyn` when their roots are available. Profile before
choosing applicable modes; never infer architecture from a project name.

For each run retain an anonymized record: size, duration, memory, coverage, failures, truncation,
findings by source/rule/priority/confidence/root cause, checklist/data-map coverage, human TP/FP/
unknown/accepted/fixed decisions when available, manual misses, duplicate rate, review time, and
before/after changes.

Calibrate rules against structurally different repositories, including benign near-misses, before
raising confidence or enabling a policy failure. Project-specific patterns may become generic rules
only after the same invariant is demonstrated independently.

Raw private source and secrets stay outside this repository. Generic fixtures may be derived only
after removing project-specific identifiers and sensitive content.

Gate: different projects produce useful, different results; repeated false positives are fixed or
downgraded; no broad accuracy claim relies only on synthetic fixtures.

Current workflow-v32 corpus pass produces 156 candidates across five projects after increasing the
bounded snapshot to cover all 5,980 supported files. All five snapshots and structural profiles are
complete. Detector tuning removed known generic ID-lookup, comment, design-token, current-path, and
recognized-validation noise without weakening the 55-case synthetic benchmark. The aggregate
truthfully reports zero reviewed candidates and keeps `accuracyClaimReady` false until the
independent review ledgers are populated.

## Phase 7 — bounded correction loop

The audit stays read-only. A separate, authorized coding-agent flow consumes one task at a time:

1. verify the candidate against source and project context;
2. record `confirmed`, `false_positive`, `inconclusive`, or `needs_human` with cited evidence;
3. change only allowed paths within configured file/line limits;
4. commit one coherent correction with its focused test;
5. run only declared and independently authorized verification commands;
6. rerun CodebaseScan and generate a before/after result;
7. record file, command, exit status, duration, and output digest provenance.

The versioned external verification ledger now covers command arguments, working-directory class,
exit status, duration, output digest/size, truncation, executor claim, and network claim. It binds
to the baseline plan and both audit snapshots. `codebasescan finalize` produces a new static report
from existing artifacts; it does not execute or repeat target code. Exact declared commands are
applied, unmatched commands remain visible, and incomplete declared verification keeps a resolved
lifecycle task partial. Changed-file digest attestation and signed executor identity remain open.

Portable CLI review uses a separate, explicitly supplied ledger. It carries only confirmed,
false-positive, or accepted-risk decisions whose project, finding fingerprint, and evidence
source-file digests still match. A fixed decision is never carried forward; disappearance in a
fresh audit is the evidence. Stale and unmatched ledger entries remain visible.

Authentication policy, authorization policy, tenant model, database migrations, billing semantics,
destructive operations, and public deployment require human authorization. A dirty worktree,
command outside the allowlist, unexpected file expansion, failed focused test, or new critical
finding stops automatic correction.

Local gate passed on `seusaas`: the baseline plan, six exact external command records, a fresh
after audit, and the finalized static report were bound and validated end to end. All six records
were applied, none were unmatched, and the report correctly kept all 61 security tasks open even
though their declared test, build, and rescan checks passed. The pass also exposed and fixed
line-only lifecycle churn for source findings. Signed executor identity and changed-file
attestation remain release hardening rather than completed guarantees.

## Phase 8 — human report

Lead with confirmed candidates, important unknowns, and failed/partial coverage; grouped root
causes; applicable checklist and data map; separated dependency/maintenance sections; before/after
progress; verification provenance; and links to JSON, SARIF, SBOM, agent plan, bundles, and schemas.

Add configurable policy profiles (`advisory`, `balanced`, and `strict`) with deterministic CLI exit
codes. Policy evaluates severity, confidence, novelty, coverage health, and accepted/suppressed
state; it does not reinterpret evidence or claim compliance. Publish the policy decision as JSON.

Implemented: static exports publish a validated policy result and schema. `balanced` supports
new-only baseline adoption, while `strict` includes existing debt; incomplete blocking coverage
uses a distinct exit code from finding failure.

Implemented: a stable script-free root presents the newest audit and immutable bounded history.
Detailed identifiers stay available in machine artifacts while the human view leads with evidence,
impact, uncertainty, and next review action.

Keep raw detail lazy and bounded. Accessibility, mobile layout, script-free static output, and
truthful empty/error states are release gates.

## Phase 9 — optional structured AI

AI consumes only opaque evidence IDs and bounded related context. Its versioned workflows are:

1. investigate a deterministic finding;
2. investigate an applicable checklist gap;
3. synthesize a report from existing IDs only.

Results include assessment, cited IDs, controls found, missing evidence, impact, preconditions,
remediation choices, verification plan, confidence, limitations, provider/model, latency, tokens,
cost, cache state, and redaction state. Invalid citations or schema fail closed. AI never creates a
verified finding or completion state by itself.

Before any provider call, a deterministic redaction gate removes secret values, credentials,
personal data candidates, absolute private paths when unnecessary, and unrelated source. The
request manifest records redaction rules, retained evidence IDs, byte/token budget, and digest;
raw prompts and responses remain local unless the user explicitly authorizes retention.

Gate: disabled mode makes zero calls; mocks cover failures and budgets; live economical/strong/local
comparisons require explicit credential, spend, or download approval and measure accepted value.

## Phase 10 — release hardening

- clean-clone installation and package-content checks on supported platforms (implemented for
  Linux/WSL, Node 22.16/24, npm/pnpm/Yarn);
- incremental/cache behavior keyed by snapshot, scanner, workflow, safe variant, and structural
  profile version (implemented for deterministic scanners; cross-snapshot file-level incrementality
  remains future work);
- abrupt-failure and resource-limit matrix for external scanners;
- CLI help, init, doctor, JSON configuration schema, package contents, and correction-flow guide;
- versioned run manifest, coverage manifest, policy-result schema, policy profiles, and stable exit
  code contract;
- scoped suppression file with expiry/staleness checks and an audit trail;
- reviewer identity/signature policy above the current unauthenticated portable ledger;
- explicit finding lifecycle for new, confirmed, accepted, fixed, stale, and reappearing work;
- parser fuzzing, malformed-repository tests, deterministic replay, and hostile-input containment;
- signed release artifacts, checksums, a CodebaseScan SBOM, and pinned scanner compatibility data;
- externally generated Axe evidence import and static-report accessibility checks; a fresh
  comprehensive browser audit remains;
- public project/package naming review and private vulnerability route; formal legal trademark
  clearance remains the maintainer's release decision.

Docker, CI integrations, Kubernetes, Terraform, hosted teams, billing, and public deployment stay
outside this roadmap until local package and evidence-quality gates are complete.

## Execution order

1. Agent output and schema.
2. Project context and data map.
3. Offline modes and paired rules.
4. Root-cause grouping, prioritization, and rule-quality metadata.
5. Correlated risk paths, contract consistency, monorepo ownership, and diff mode.
6. Corpus audits and calibration.
7. Authorized `seusaas` correction loop.
8. Human report refinement.
9. Optional AI validation.
10. Release hardening.

Every phase ends with formatting, typecheck, lint, unit tests, graph tests, benchmark, build, package
test, and relevant browser tests. Commit each independently reviewable behavior change.
