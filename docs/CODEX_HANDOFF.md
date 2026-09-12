# Current handoff

## Product state

CodebaseScan is a deterministic, local-first source-audit CLI for authorized Node.js, JavaScript,
TypeScript, React, and Next.js repositories. It captures a bounded snapshot, parses target code and
configuration as untrusted data, runs the audit pipeline, and exports a human report plus
machine-readable automation and external-agent contracts. It never installs or runs the target
project.

Current contracts:

- audit workflow `codebasescan-audit-v69`;
- audit-mode pack `1.0.0`;
- audit report schema v17;
- rule-quality schema v3;
- agent plan v5, task bundle v3, agent report v1, and review-rule pack v1;
- static report manifest v1;
- one current report root updated in place, with legacy history roots still readable.

The packaged CLI has no LangChain, LangGraph, model provider, SQLite, Next.js, or React runtime
dependency. The one-shot audit uses an ephemeral store. The optional repository UI and worker load
the persistent SQLite store only when those commands are selected.

Implemented analysis includes project/profile mapping, bounded call relationships, AST and SaaS
security, Next.js and React checks, static accessibility, privacy, reliability, environment, test,
API, database, webhook, feature-flag, supply-chain, dependency, quality, dead-code, duplication,
release, and web-posture evidence. Optional trusted Semgrep/Gitleaks, a local OSV cache, imported Axe
output, and the explicit one-URL HTTP probe retain separate coverage.

Static output includes the human dashboard, complete report, run manifest, policy, SARIF,
CycloneDX, Markdown, schemas, hashes, and versioned agent rules/plans. The bundled Codex skill is the
reference external-agent workflow; it is not part of audit execution.

No production scanner or configuration default contains reference-project names or paths.

## Continuation rules

- Read `VALIDATION.md` and `ARCHITECTURE.md` before changing behavior.
- Keep scanner evidence, missing evidence, external-agent hypotheses, and human disposition
  separate.
- Never execute target JS/TS configuration, plugins, lifecycle scripts, tests, or application code.
- Every new source rule needs a vulnerable case and a benign control before integration.
- Prefer small commits and update workflow/checklist versions when persisted behavior changes.
- New runs update one managed report root. Do not silently reintroduce default audit history.
- Calibrate new adapters from reproducible failures across structurally different authorized apps.

## Next evidence needed

The generic SaaS pack still needs independent owner-confirmed real-project ground truth. Existing
calibration repositories are pressure and portability references, not security verdicts. Add
provider, ORM, authentication, job, queue, WebSocket, upload, or framework shapes only from
reproducible missed evidence. Runtime business authorization, RLS, provider dashboard settings,
token one-time use, and deployment controls remain outside source-only proof.
