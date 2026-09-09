# Contributing

Read `AGENTS.md` and the threat model before changing scanning or inference. The project favors a small, readable, evidence-led product over broad unsupported security claims.

Use English for code, docs, and UI. Use descriptive functions and focused modules. Submit positive and benign tests for new detection rules. Preserve intentional false-positive fixtures; do not tune tests merely to advertise a perfect score.

Run the validation commands in the README and disclose checks you could not run. Once the real lockfile is committed, install with `npm ci`. Do not include real secret matches, proprietary source, generated databases, or local model weights in commits.

Use conventional descriptive commit messages when useful, such as `feat: add snapshot-bound source evidence` or `fix: retain failed scanner coverage`. Describe user impact, security boundaries, and validation in pull requests. Large architecture changes require a concise entry in `docs/DECISIONS.md`.

The initial code uses Apache-2.0. By submitting changes, contributors should ensure they have permission to contribute them under the repository license. Do not copy incompatible third-party scanner rule packs into `configs/`.
