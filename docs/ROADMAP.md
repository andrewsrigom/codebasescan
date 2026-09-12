# Roadmap

CodebaseScan is moving toward one clear product: a deterministic CLI that audits a JavaScript
codebase and updates a portable coverage-style report. The report is useful to people, CI, and a
coding agent chosen by the user.

## Ready now

- project-local npm CLI with `init`, `doctor`, `audit`, `open`, policy, baseline, review,
  suppression, calibration, and agent-bundle commands;
- bounded snapshots that never execute target code or executable configuration;
- nine audit modes for Node.js, TypeScript, JavaScript, React, Next.js, and common SaaS mechanics;
- TypeScript/AST, framework, supply-chain, accessibility, privacy, reliability, release, web, and
  maintainability analysis;
- optional trusted Semgrep/Gitleaks, offline OSV evidence, imported Axe output, and an explicitly
  approved one-URL posture probe;
- one current script-free report with JSON, SARIF, CycloneDX, schemas, policy, provenance, and
  artifact hashes;
- reusable GitHub Action with full-context baseline comparison, HTML artifacts, SARIF, and policy
  exit codes;
- versioned external-agent rules, plans, report contracts, and a bundled Codex review skill;
- benchmark fixtures, real-project portability runs, npm/pnpm/Yarn package smoke tests, and guarded
  public releases.

## Phase 1 — release stabilization (completed for v0.3.0)

1. finish the 0.3 release gate after the deterministic engine and report migration;
2. verify upgrade behavior from legacy report-history roots;
3. validate the packed package on npm, pnpm, Yarn, Node 22.16, and Node 24;
4. regenerate the public demo and fixture exports from the current engine;
5. publish only after README, changelog, schemas, package contents, tag, and provenance agree.

## Phase 2 — trustworthy results

1. independently label candidates in at least five structurally different authorized repositories;
2. record manual misses and false-negative review scope rather than inferring recall;
3. turn repeated false positives and misses into paired vulnerable/benign regression fixtures;
4. publish per-rule evidence, location, and explanation quality without inventing a global score;
5. add provider, ORM, auth, queue, upload, WebSocket, and monorepo shapes only from reproducible
   evidence.

The existing multi-project corpus proves bounded execution and portability, not generic accuracy.
`accuracyClaimReady` must remain false until independent review is complete.

Current calibration has 54 completely reviewed candidates across four authorized snapshots: 39 true
positives, 2 false positives, and 13 not applicable. Three snapshots have bounded false-negative
samples, but the corpus review remains incomplete and no recall claim is made.

## Phase 3 — complete CLI cycle

1. add documented CI examples for advisory, balanced, and strict policies;
2. make changed-files and baseline workflows easy for pull requests without hiding existing debt;
3. improve report navigation from summary to root cause, exact evidence, coverage, and next check;
4. add machine-readable version negotiation and migration notes for every public artifact;
5. support opt-in retention outside the default report, such as CI artifacts or a user-owned
   directory, without rebuilding product-managed history.

The GitHub Action, baseline-only PR gate, report artifact upload, and SARIF upload are implemented.
Changed files are not parsed in isolation: the scanner retains full repository context and the
baseline policy limits blocking to newly introduced findings.

## Phase 4 — broader deterministic coverage

Priority order:

1. richer static accessibility semantics and stronger imported Axe provenance;
2. API, database, environment, webhook, feature-flag, and test-evidence correlation;
3. authentication/session libraries, authorization wrappers, tenant boundaries, billing, jobs,
   queues, uploads, and outbound integrations seen in real SaaS repositories;
4. passive deployment evidence imports such as headers, route inventories, and platform manifests;
5. optional repository sharding beyond the current bounded snapshot.

Robots, sitemap, metadata, and optional `llms.txt` stay inside web posture; they are useful coverage,
not separate products.

## Phase 5 — external agent interoperability

1. stabilize the generic agent report/rule/plan schemas;
2. keep the Codex skill as the reference implementation and document equivalent Claude usage;
3. require manifest validation, evidence citations, explicit uncertainty, and separate hypotheses;
4. let agents propose reviews or patches only under their own authorization;
5. compare a fresh deterministic scan against a preserved baseline after corrections.

CodebaseScan will not add a built-in model provider merely to claim AI support. An agent integration
must reduce review work while preserving deterministic evidence and user control.

## Deliberately later

Native platform claims, signed reviewer identity, authenticated runtime browser/API collection,
Docker execution, Kubernetes, Terraform, cloud IAM, DAST, exploitation, hosted teams, RBAC,
billing, and compliance certification require separate validation or threat models.
