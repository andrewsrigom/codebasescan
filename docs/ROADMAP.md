# Roadmap

## Milestone 0 — Prove the current vertical slice

Complete the handoff P0 gate. Produce a real lockfile, build, graph persistence tests, actual UI screenshots, and a reproducible demo. Do not expand scanning breadth before this works.

## Milestone 1 — Make results trustworthy

Add golden schemas from pinned real scanner versions, explicit version reporting, source metadata/ruleset digests, tested crash recovery, append-only review/report revisions, storage migration guards, and better redacted diagnostics. Split the large workspace component when extending its tabs. Run browser accessibility and no-egress checks.

## Milestone 2 — One valuable detection upgrade

Choose either AST-aware authorization candidate discovery for one narrowly defined Next.js route pattern, or resolved lockfile inventory plus OSV matching with downloaded cache timestamps. Include middleware/RLS counterexamples, stale cache, unsupported lockfiles, no fixed version, multiple installed versions, and indirect dependencies. No unsupported “reachable” flag.

## Milestone 3 — Evaluate the optional AI honestly

Define a reviewed dataset with evidence-level labels and benign controls. Compare the deterministic baseline with the same scanner results plus local contextual analysis. Measure false confirmations (target zero by product contract), invalid citations, missed context, abstentions, time, and hardware/model settings. No single broad “security accuracy” score from a handful of fixtures.

## Milestone 4 — Distribute responsibly

Validate name/licenses, document supported OS and pinned tool versions, add a useful install path, release artifacts, and GitHub Action/SARIF compatibility tests. Avoid publishing a privileged all-in-one image until its isolation and update strategy are reviewed. Add CI policies only after baseline/finding identity semantics are defined.

## Deliberately later

Trivy, broad AI/agent threat analysis, MCP integration, a human-approved patch proposal workflow, cloud/team features, and paid services all require independent justification. This portfolio does not need all of them to show useful engineering.
