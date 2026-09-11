# Roadmap

The detailed engineering sequence lives in
[Autonomous audit roadmap](AUTONOMOUS_ROADMAP.md). This page tracks the product boundary and the
remaining gates.

## Current release — 0.2.1

CodebaseScan now has the intended local CLI workflow:

1. install it as a project development dependency;
2. run `codebasescan init` and `codebasescan doctor`;
3. run one command against an authorized repository;
4. receive a stable `codebasescan-report/index.html` with newest result and immutable history;
5. use the same directory as a static hosted report when its contents are safe to expose.

The default offline audit has nine selectable modes for Node.js, JavaScript, TypeScript, React, and
Next.js projects. It emits a human report plus versioned JSON, agent plan, run manifest, policy,
SARIF, CycloneDX, Markdown, contract, comparison, and integrity artifacts. Missing or partial
coverage is explicit and there is no global security score.

Implemented release work:

- bounded source snapshots that never load target code or executable configuration;
- deterministic security, SaaS, Next.js, React, accessibility, privacy, reliability,
  maintainability, supply-chain, release, and web-posture checks;
- npm, pnpm, Yarn Classic/Berry lockfile parsing and clean package-install smoke tests;
- optional trusted Semgrep/Gitleaks, offline OSV cache, and explicitly approved single-URL probe;
- optional import of externally generated Axe results without running a target browser;
- safe JSON/JSONC project vocabulary and editor schema;
- CLI help, non-interactive CI behavior, phase/timing output, simple errors, and report reopening;
- baseline lifecycle, suppressions, human dispositions, policy exit codes, and focused agent bundles;
- LangGraph orchestration with in-memory CLI checkpoints and optional persistent SQLite review;
- script-free static report root, latest pointer, immutable bounded history, and artifact hashes;
- Node 22.16/24 CI plus npm, pnpm, and Yarn clean-install coverage;
- dependency split that keeps Next.js/shadcn UI, SQLite, and Ollama out of the default CLI install;
- MIT license, English public documentation, contribution/security policies, public repository,
  private vulnerability reporting, and guarded provenance metadata.

Version 0.2.1 is published on npm and the matching public GitHub release is available. Publication
remains manual and is not triggered by ordinary pushes.

## Next release — confidence and calibration

- finish independent candidate labels for five structurally different repositories;
- record manual misses and false-negative review scope instead of inferring recall;
- use repeated false positives to narrow generic detectors and add paired regression fixtures;
- publish evidence, location, and explanation-quality counts per rule;
- keep `accuracyClaimReady` false until the declared review is actually complete.

## Evidence still needed after 0.2

These are product maturity items, not reasons to hide current coverage:

- independent owner-confirmed review of findings, false positives, and manually found false
  negatives across structurally different SaaS projects;
- optional sharding for repositories beyond the current 4,000-file / 32 MiB bounded snapshot;
- native Windows and macOS gates before claiming those platforms; 0.2 supports Linux/WSL;
- externally supplied authenticated browser/API evidence for runtime accessibility and deployed
  controls, with its own authorization and provenance contract;
- signed release artifacts and stronger reviewer/executor identity;
- dependency license policy and broader npm/Yarn transitive parent-path fidelity;
- new framework/provider/ORM shapes only when real projects expose a reproducible miss.

The latest calibration corpus is `seusaas-platform`, `robs-web`, `capta-core`,
`aster-streaming-platform`, and `severyn`. The current workflow-v31 pass captured all 5,980
supported files without snapshot truncation and produced 156 candidates. The versioned aggregate
tests portability and detector behavior; reviewer labels and false-negative review remain
incomplete, so it is not an accuracy claim.

## Deliberately later

AI-assisted investigation, automated fixes, Docker/CI target execution, Kubernetes, Terraform,
cloud IAM, broader DAST, exploitation, hosted teams, RBAC, billing, and compliance certification
remain separate projects with separate threat models. Mechanical source evidence stays useful
without them.
