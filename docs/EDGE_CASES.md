# Edge cases and explicit behavior

“Implemented” means code exists. See `VALIDATION.md` for executed layers.

| Case                                                                                | Behavior                                                                                                                     |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| AI disabled                                                                         | Deterministic audit completes with `DISABLED` AI coverage and zero AI calls                                                  |
| Ollama/OpenAI unavailable, timeout, malformed output, or invented evidence ID       | Finding is retained; assessment becomes inconclusive; no provider fallback                                                   |
| AI says false positive                                                              | Assessment only; scanner severity and human disposition stay unchanged                                                       |
| OpenAI budget/cache                                                                 | Calls reserve persisted budgets; cache hits use the same prompt/model/finding/evidence/context key and do not make a request |
| Repository asks for secrets/files/policy changes                                    | Text stays untrusted data; only captured safe relative paths are readable; `.env`/key paths remain excluded                  |
| Human publishes unresolved findings                                                 | Allowed with rationale; publication does not confirm them                                                                    |
| Scanner disabled/missing/fails                                                      | `DISABLED`/`FAILED`, never “zero findings” coverage                                                                          |
| Semgrep/Gitleaks nonzero/malformed/oversized output                                 | Known contracts are normalized; unsupported states fail or become partial                                                    |
| Same code flagged by multiple independent scanners                                  | Sources remain separate unless the narrow static/runtime posture reconciliation applies                                      |
| Static header missing but approved response contains it                             | Static candidate remains, runtime evidence records `observed_safe`; routes/environments can differ                           |
| Static and runtime posture both detect the same weakness                            | One candidate contains declared and observed evidence instead of a duplicate                                                 |
| HTTP target is localhost                                                            | Allowed after explicit per-audit approval                                                                                    |
| HTTP target is RFC1918/ULA                                                          | Rejected unless private-network approval is explicitly set                                                                   |
| HTTP target/redirect reaches metadata, link-local, reserved, or mixed forbidden DNS | Rejected before connection; redirect targets are validated again                                                             |
| Server rejects HEAD                                                                 | One bounded GET fallback is allowed only for 405/501                                                                         |
| Response hangs, redirects repeatedly, or is too large                               | Probe is `FAILED`; no clean runtime result is implied                                                                        |
| Lockfile absent                                                                     | Manifest ranges remain inventory; OSV is `NOT RUN`/skipped rather than querying ranges                                       |
| npm/pnpm/Yarn lockfile malformed                                                    | Dependency coverage is failed/partial, not clean                                                                             |
| Multiple installed versions                                                         | Each resolved package/version/lockfile entry remains distinct                                                                |
| Direct vs transitive cannot be proved                                               | Relationship is `unknown`; no reachability claim                                                                             |
| OSV aliases duplicate an advisory                                                   | Alias-overlapping records are consolidated; withdrawn records are ignored                                                    |
| OSV stale/unavailable                                                               | Fresh local cache may be used; otherwise coverage is `FAILED`                                                                |
| OSV has no fixed version/CVSS                                                       | Field stays empty/unspecified; Traceward does not invent it                                                                  |
| `.env`, key, binary, symlink, generated tree                                        | Excluded and counted; this limits coverage                                                                                   |
| Source changes before graph resume                                                  | Audit fails instead of mixing snapshots                                                                                      |
| Huge/deep repository                                                                | Snapshot and finding budgets truncate with explicit partial coverage                                                         |
| Browser closes                                                                      | Separate worker continues persisted work                                                                                     |
| Two workers                                                                         | Local PID lock rejects the second                                                                                            |
| Worker dies                                                                         | Active work is requeued up to the bounded attempt count; abrupt crash testing remains incomplete                             |
| Cancellation races completion                                                       | Cancelled is terminal and late progress cannot overwrite it                                                                  |
| Audit comparison says resolved                                                      | Fingerprint disappeared; this is not proof of remediation, and line moves can appear new/resolved                            |
| CI gate passes                                                                      | Only configured severity threshold passed for observed unresolved findings; not a security assurance                         |
| HTML/Markdown contains hostile text                                                 | React/HTML escaping is applied; external Markdown renderers remain responsible for safe rendering                            |
| Imported/tampered application DB                                                    | Unsupported; persisted-report schema validation and migration hardening remain incomplete                                    |
| Native Windows/macOS                                                                | Not validated; WSL2/Linux is the supported tested path                                                                       |
| No findings                                                                         | “No candidates in analyzed scope,” never “secure”                                                                            |
