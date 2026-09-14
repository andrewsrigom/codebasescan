# Version 1 offline acceptance contract

CodebaseScan v1 is complete when the deterministic CLI is dependable for its declared scope. It
does not mean that every vulnerability in every application can be detected. Unsupported,
unobserved, and runtime-only behavior must remain explicit.

## Supported scope

The v1 support claim is limited to authorized Node.js repositories containing JavaScript,
TypeScript, React, or Next.js. The default audit remains local, read-only, non-interactive, and
network-free. Other languages, native platforms, containers, infrastructure, authenticated DAST,
and hosted collaboration do not block v1.

## Release gates

### Result quality

- At least 10 structurally different authorized repositories are included in the versioned
  calibration record.
- At least 200 emitted candidates have source-backed review labels.
- Overall observed sample precision is at least 85%.
- Critical and high observed sample precision is at least 90%.
- At least 95% of reviewed candidates have correct locations and sufficient evidence.
- Actionable duplicate candidates remain below 5% of the reviewed sample.
- Every repository receives a bounded false-negative review and at least three receive a complete
  review of the declared source-only checklist.
- Every reproducible scanner-caused miss and repeated false positive has paired vulnerable and
  benign regression coverage. No known reproducible miss remains without a tracked regression.
- Recall is reported only when the calibration contract supports it. Completing v1 does not by
  itself authorize a generic recall or security-certification claim.

Not-applicable and inconclusive labels do not count as true or false positives. The calibration
record must publish their totals and the exact review scope separately.

### Report usefulness

- One command updates one portable current report containing script-free HTML, JSON, Markdown,
  SARIF, CycloneDX, policy, provenance, coverage, and integrity artifacts.
- Every displayed candidate explains the problem, potential impact, exact evidence, review
  uncertainty, and the next verification step in plain language.
- Internal identifiers remain available for automation but do not dominate the default human view.
- Zero findings, disabled analysis, unsupported analysis, incomplete coverage, and scanner failure
  remain visually and mechanically distinct.
- Every public artifact validates against its declared schema and version.

### Safety

- A default audit never executes, imports, installs, builds, tests, probes, or modifies the target
  repository.
- A default audit performs no network request.
- Snapshot containment, symlink rejection, hostile paths, bounded input, timeout, report escaping,
  and report-integrity tests pass.
- Raw secret values never reach reports, logs, caches, UI state, or external-agent artifacts.
- Optional network and Git-history operations require explicit authorization and preserve their
  separate coverage state.

### Portability and performance

- Clean package tests pass on Node.js 22 and 24 with npm, pnpm, and Yarn.
- Linux and WSL are verified release environments. Any additional native platform claim requires
  its own clean-install and audit evidence.
- A complete default audit of a representative project with up to 2,000 supported files and no
  snapshot truncation finishes within 120 seconds on the documented reference environment.
- The packed CLI is at most 2 MiB and a clean default installation is at most 60 MiB, excluding
  optional external scanner binaries and their caches.
- CI completes its deterministic validation and package matrix within 10 minutes under the
  documented GitHub-hosted environment.

### Release integrity

- Formatting, type checking, lint, core tests, integration tests, benchmark, production build,
  package tests, browser tests, package audit, and CLI diagnostics pass.
- The declared fixture benchmark has no regression from its versioned ground truth.
- Baseline CI blocks only policy-relevant new findings while retaining existing debt and coverage.
- Two consecutive full acceptance runs pass without a critical product regression.
- README, changelog, schemas, public demo, package contents, tag, provenance, and release metadata
  describe the same version.

## Completion rule

The v1 gate passes only when every mandatory item above has current evidence. A waiver must name
the failed item, owner, rationale, evidence, and expiry; it cannot convert missing evidence into a
pass. Work outside the supported scope stays on the roadmap and does not delay the deterministic
offline release.
