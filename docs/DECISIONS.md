# Initial engineering decisions

| Decision                                             | Rationale / consequence                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Local-first, single user                             | Avoid uploading proprietary repositories and avoid premature SaaS infrastructure. No public hosting mode.                                                                                                                                                                                                                       |
| Next.js + TypeScript                                 | Strong product UI and shared readable domain contracts. Node 22.16+ enables the selected native TypeScript/SQLite execution path.                                                                                                                                                                                               |
| Separate worker                                      | Audits and human-resume requests survive browser closure. No fire-and-forget audit in a route handler.                                                                                                                                                                                                                          |
| SQLite, one consumer                                 | Minimal setup for one machine. Not a distributed queue or multi-host deployment architecture.                                                                                                                                                                                                                                   |
| Official LangGraph SQLite saver                      | Learn real framework persistence; do not simulate checkpoints using a JSON file.                                                                                                                                                                                                                                                |
| No AI by default                                     | A reproducible demo must not require hardware, model downloads, keys, or fake model activity.                                                                                                                                                                                                                                   |
| Explicit Ollama or OpenAI provider                   | Ollama is fixed to loopback. OpenAI is opt-in, uses bounded redacted context, structured output, no tools, and `store=false`.                                                                                                                                                                                                   |
| Separate network opt-ins                             | OSV, OpenAI, and the one-URL HTTP probe are independently enabled; enabling one never authorizes another.                                                                                                                                                                                                                       |
| Patterns + posture + optional scanners               | Built-in candidates, application-posture checks, Semgrep, Gitleaks, and lockfile-based OSV matching expose distinct coverage.                                                                                                                                                                                                   |
| Safe HTTP posture probe                              | One explicitly approved URL, HEAD-first, bounded redirects/time/bytes, DNS validation and IP pinning; no crawl or exploitation.                                                                                                                                                                                                 |
| Source snapshot before analysis                      | Give tools a bounded fixed in-memory view and evidence digests. Exclude credentials files and unsupported inputs.                                                                                                                                                                                                               |
| No shell or target execution                         | Scanner subprocesses are trusted fixed binaries, not model-chosen commands or target scripts.                                                                                                                                                                                                                                   |
| No automatic exploit or fix                          | Verification means evidence review, not a claim of exploitation. Future dynamic tests require a separate threat model.                                                                                                                                                                                                          |
| No numeric security score                            | A high number could imply assurance unsupported by coverage. Display findings, coverage, and dispositions instead.                                                                                                                                                                                                              |
| Explicit coverage states                             | COMPLETE, PARTIAL, FAILED, NOT RUN, DISABLED, NOT SUPPORTED, and NOT PERFORMED prevent missing analysis from looking clean.                                                                                                                                                                                                     |
| AI cannot change scanner truth                       | Model output adds contextual assessment only; it cannot suppress findings, lower scanner severity, or publish a report.                                                                                                                                                                                                         |
| Human publication separate from finding confirmation | Reviewing a report must not falsely confirm every candidate.                                                                                                                                                                                                                                                                    |
| Explicit limitations in every export                 | Portable artifacts must preserve uncertainty even when viewed outside the app.                                                                                                                                                                                                                                                  |
| Custom CSS and system fonts                          | Small UI dependency surface, offline assets, readable components. No forced component library migration.                                                                                                                                                                                                                        |
| Apache-2.0 for original starter                      | Explicit open-source intention. External binary, rules, and model licenses must be reviewed separately.                                                                                                                                                                                                                         |
| No bundled binary/model/font files                   | Keep redistribution auditable and the starter lightweight.                                                                                                                                                                                                                                                                      |
| Pinned mechanical scanner packages                   | dependency-cruiser and jscpd run offline from Traceward-owned dependencies with fixed arguments; target scanner configuration is never loaded.                                                                                                                                                                                  |
| Isolated Knip execution                              | Knip receives captured source, script-free sanitized workspace manifests, and a generated config that disables all target plugins. Bounded declarative exclusions, aliases, workspaces, and entry hints reduce noise without executing target configuration. Its output is maintenance evidence, never a vulnerability verdict. |
| Declarative SaaS semantics                           | A root JSON/JSONC file may extend fixed identifier/helper lists and constrained public routes. It cannot provide code, regex, plugins, arbitrary paths, or suppressions. The declared name must still appear in captured source, and coverage/limitations remain visible.                                                       |
| Optional report schema v5 data                       | New audits add supply-chain and code-quality analysis. Stored v1-v4 reports remain readable, are not rewritten, and omit optional fields. Workflow v5 prevents old in-progress checkpoints from resuming into changed deterministic analysis.                                                                                   |

Changes to these decisions should be deliberate. Add a dated decision with the problem, alternatives, trade-offs, and migration impact. Do not create endless documentation for ordinary implementation details.

## 2026-09-10 — agent plan contract v2

The remediation plan is now also emitted as the primary `agent-plan.json`, with a generated JSON
Schema. Version 2 adds cause grouping, explainable priority factors, confidence, exposure, change
risk, automatic-fix eligibility, human-authorization flags, expected changes, and structured
verification-command allowlists. `remediation-plan.json` remains a byte-identical filename alias so
existing report consumers can move deliberately; its payload also carries schema version 2. Version
1 plans were external generated artifacts rather than stored audit state and are not rewritten.

## 2026-09-10 — applied rule quality artifact

Rule quality is emitted separately as `rule-quality.json` plus a JSON Schema. It reports only rules
that produced findings in the audit, keeps fixture measurements separate from real-project human
dispositions, and states detector limitations instead of presenting one unsupported accuracy score.

## 2026-09-10 — intrinsic JSX accessibility semantics

Static accessibility rules preserve JSX tag casing. A React component such as `Input` is not
treated as the intrinsic `input` element, and an intrinsic wrapper forwarding spread attributes is
left unverified because its accessible name may be supplied by the caller. Exact static or dynamic
`htmlFor`/`id` expressions remain linkable. Scanner version 0.2.0 and workflow v14 prevent old
results from being presented as current calibration.

## 2026-09-10 — corpus-calibrated privacy and reliability semantics

Privacy log analysis inspects payload expressions rather than matching sensitive words in static
human-readable messages. Template interpolations remain analyzable. Reliability rule TW-REL002 now
means an undocumented empty catch; a comment explaining a narrow intentional ignore is retained as
review context without becoming a finding. The scanners and audit-mode pack move to 0.2.0 and the
workflow moves to v15.

## 2026-09-10 — declared context and observed data map

Safe Traceward JSON/JSONC configuration may add bounded project context and manifest-verified script
names. The audit still executes neither configuration nor scripts. Declared context keeps separate
provenance from an observed, source-derived data map. Both fields are optional additions to report
schema v5, so stored earlier reports remain readable and are not rewritten. Workflow v11 prevents an
in-progress older graph from resuming into the changed profiler behavior.

## 2026-09-10 — bounded static audit modes

Accessibility, privacy, and reliability start as small Traceward-owned AST scanners rather than new
third-party engines. Their nine rules have declared vulnerable and benign benchmark cases and retain
source-only limitations. They add optional findings to report schema v5 without rewriting existing
reports. Workflow v12 prevents old in-progress checkpoints from resuming into the expanded fan-out.

## 2026-09-10 — explicit mode selection

All eight offline modes run when no selection is supplied. CLI/API callers may choose a bounded
subset; unrelated graph nodes still publish explicit skipped runs so coverage becomes `DISABLED`
rather than clean. Reports store the versioned selection. Stored options and reports gain optional
fields only, while workflow v13 protects in-progress checkpoint compatibility.
