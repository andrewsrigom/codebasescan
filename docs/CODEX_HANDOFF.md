# Current handoff

## Product state

Traceward is a local-first source audit tool for authorized Node.js, JavaScript, TypeScript,
React, and Next.js repositories. The default path is offline and AI-disabled. It captures a
bounded snapshot, parses target code/configuration as untrusted data, runs deterministic scanners,
and exports a human report plus machine-readable remediation artifacts. It never installs or runs
the target project.

The audit workflow is `traceward-audit-v26`. Twenty-four scanner/profile results fan into
normalization. The audit-mode pack is `0.8.0`. The generic SaaS layer consists of:

- safe root `traceward.config.json`/JSONC semantics;
- bounded declared project context, verified script names, and an observed data map;
- static accessibility, privacy, and reliability candidate scanners with paired controls;
- eight composable mode selections with default-complete execution and explicit disabled coverage;
- project vocabulary and wrapper aliases visible in the project profile;
- a dedicated `saas-security` scanner with nine source rules;
- bounded source-risk paths backed by entrypoint IDs, resolved call IDs, exact symbol ranges,
  sensitive-operation fact IDs, and related finding IDs;
- sanitized environment-template names compared with `process.env` and `import.meta.env` usage;
- tenant, rate-limit, webhook-idempotency, CSRF, billing, recovery, and OAuth controls;
- paired vulnerable and benign unit/benchmark cases.
- bounded workspace package-export and imported-reexport resolution.
- bounded security-critical test-reference evidence without executing target tests.
- captured OpenAPI/Swagger operation consistency against mapped Next.js and Express routes.
- captured Prisma/Drizzle/SQL schema, migration, and source-entity consistency.
- lifecycle diff v2 with local-history recurrence and per-component summaries.
- agent-plan v5 and task-bundle v3 component/test context for focused authorized corrections.

No production scanner or configuration default contains reference-project names or paths.

## Continuation rules

- Read `VALIDATION.md` and `ARCHITECTURE.md` before changing behavior.
- Keep scanner evidence, missing evidence, AI assessment, and human disposition separate.
- Never execute target JS/TS configuration, plugins, lifecycle scripts, tests, or application code.
- Every new source rule needs a vulnerable case and a benign control before integration.
- Prefer small commits and update workflow/checklist versions when persisted behavior changes.
- Calibrate new adapters from reproducible failures across structurally different authorized apps.

## Next evidence needed

The generic SaaS pack still needs independent owner-confirmed real-project ground truth. The
`seusaas` repository is a pressure/false-positive reference only; `robs-web` is a structurally
different portability check. Neither run is an independent security verdict. Add more provider,
ORM, job, WebSocket, upload, or framework shapes only from reproducible missed evidence. Runtime
business authorization, RLS, provider dashboard settings, token one-time use, and deployment
controls remain outside source-only proof.
