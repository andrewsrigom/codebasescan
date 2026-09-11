# Threat model

## Protected assets

Source code, accidentally embedded credentials, local files outside registered projects,
source-derived reports and caches, and the integrity of scanner and analyst decisions.

## Trust assumptions

The local OS user, CodebaseScan installation, local configuration, trusted scanner binaries, and
the fixed OSV service are trusted. Target files, filenames, comments, manifests, lockfiles, imported
artifacts, scanner/API output, HTTP targets, redirects, and response headers are untrusted. External
coding agents are outside the audit process and require separate authorization.

This is an application boundary, not a hardened sandbox. A compromised dependency/scanner, malicious same-user process, browser extension with local access, kernel/root attacker, or parser zero-day is outside the containment guarantee. Use a disposable VM/container with OS CPU/memory/egress limits for truly hostile input; a container alone is not proof of isolation.

## Controls and residual risk

| Threat                          | Implemented control                                                                                                                                                                  | Residual limitation                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| Target lifecycle/code execution | No target install, script, application, shell, or exploit execution                                                                                                                  | Trusted scanners and parsers still process hostile bytes                                                            |
| Target semantics configuration  | Only bounded root JSON/JSONC keys, identifier lists, and constrained route patterns are parsed; executable CodebaseScan config, regex, plugins, and arbitrary paths are rejected     | A project can mislabel a helper; the matching source call and applied semantics remain reviewable                   |
| Path traversal/symlink escape   | Canonical root, safe relative paths, containment checks, symlinks skipped, leaf `O_NOFOLLOW` where available                                                                         | Concurrent replacement of intermediate directories is not fully isolated                                            |
| Agent prompt injection          | CodebaseScan never invokes an agent; exported rules require report validation, untrusted-data handling, bounded tasks, and separate authorization                                    | An external agent or its operator can still ignore the contract                                                     |
| Secret/privacy leakage          | Sensitive working-tree files excluded; Gitleaks raw matches discarded; optional history scan keeps only safe metadata; report excerpts are bounded and redacted                      | Unknown secret formats, Git metadata, and sensitive business logic can remain                                       |
| Unexpected model/network cost   | The audit has no built-in model provider, credential, tool loop, or cloud fallback                                                                                                   | A separately operated coding agent has its own data and cost policy                                                 |
| Tampered persisted report       | Runtime schema validation on read/write; static manifest records artifact size and digest; loopback server serves only verified artifacts                                            | Local database and filesystem authenticity are outside the same-user trust model                                    |
| OSV source disclosure           | Fixed OSV endpoint; only npm package names/versions; bounded responses; compact private cache                                                                                        | Package inventory can disclose technology choices; advisory freshness depends on OSV/cache                          |
| Probe SSRF/metadata             | HTTP(S) only, no credentials/fragments/sensitive query keys, metadata/reserved/link-local blocks, private-network opt-in, all-address validation, DNS pinning, redirect revalidation | An approved target can still have side effects on HEAD/GET; proxy/TLS/network-layer behavior is outside app control |
| Probe resource abuse            | One URL, redirect/method/response/time limits, no body/auth/crawl/exploit                                                                                                            | Per-hop timeout means total duration can exceed one request timeout                                                 |
| Scanner resource exhaustion     | File/depth/byte caps, subprocess time/output limits, private staging, one worker                                                                                                     | External processes have no OS memory/CPU sandbox                                                                    |
| Dirty/stale evidence            | Snapshot/file digests, workflow/config compatibility versions, scanner cache keys, timestamps, and advisory modification metadata                                                    | Snapshot collection is not atomic across files                                                                      |
| Report/script injection         | React escaping; escaped standalone HTML; no report scripts/network; restrictive report CSP                                                                                           | Third-party Markdown renderers must still treat content as untrusted                                                |
| CodebaseScan CSRF/DNS rebinding | Loopback bind, exact Host/Origin policy, JSON and UI header for mutation                                                                                                             | No user authentication; never expose to LAN/public internet                                                         |
| Partial/failed analysis         | Explicit coverage states; failure never becomes zero findings                                                                                                                        | A human can still misread incomplete coverage                                                                       |
| False certainty                 | Scanner evidence, runtime evidence, external-agent hypotheses, human disposition, and coverage stay separate                                                                         | Human confirmation can be wrong; no assurance or exploitability guarantee                                           |
| Crash with staged source        | Private mode-0700 staging, normal-path cleanup, exclusive worker lock, next-start removal limited to recognized staging names, and actual worker `SIGKILL` recovery testing          | Plaintext staging remains until the next worker starts; full host power-loss behavior remains environment-dependent |

## Data lifecycle

`.codebasescan/application.sqlite` stores project paths, jobs, reports, review notes, events, and
scanner cache data for the optional local application workflow.
`.codebasescan/advisory-database.json` stores compact exact-version OSV records, including explicit
clean query results. WAL/SHM files may exist. None are encrypted by CodebaseScan; use encrypted
local storage when needed.

`.codebasescan/temporary` contains selected source while external scanners run. Normal completion deletes it; an exclusive worker removes only recognized Semgrep/Gitleaks staging directories at its next start. Exports and caches are private source-derived artifacts; inspect them before sharing. Redaction is not a data-loss-prevention guarantee.

## Security review scope

CodebaseScan checks bounded source/configuration, lockfile advisories, and one approved HTTP response. With explicit approval it can scan Git history for secret patterns, but it does not validate credential activity, prove tenant isolation or business authorization, prove dependency reachability, crawl an application, brute-force authentication, exploit targets, analyze cloud IAM/IaC, establish compliance, or certify software.
