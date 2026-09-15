---
name: codebasescan-verify-fix
description: Verify whether a separately authorized project correction changed CodebaseScan findings and tests. Use after a user-requested fix, not as permission to edit or execute the project.
---

# CodebaseScan Verify Fix

Require an explicitly supplied before report and a fresh after report. Run `codebasescan report verify` on each portable package. Compare the exact finding fingerprint, rule ID, affected source, coverage status, and snapshot digest. A finding disappearing is report change, not proof that the risk is eliminated.
Use `codebasescan changes show <before-report-root> <after-report-root>` to identify new candidates and coverage regressions before inspecting source.

Inspect the changed source and relevant tests only within the user's authorized project scope. Run target tests/builds only when separately authorized; CodebaseScan never runs them. Report commands that were not run as `not run`, not passing. Keep agent assessments and human disposition outside deterministic scanner output.

Return a short before/after summary: remaining candidates, new candidates, coverage regressions, source/test evidence, verification not performed, and residual uncertainty. Do not edit code, suppress findings, publish reports, or call a deployed app unless the user separately asks for that action.
