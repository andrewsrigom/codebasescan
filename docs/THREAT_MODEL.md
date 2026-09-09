# Threat model

## Protected assets

Source code, credentials accidentally present in source, local files outside registered projects, model context, source-derived reports/checkpoints, and the integrity of the analyst's decision.

## Trust assumptions

The local OS user, Traceward's installed dependencies, scanner binaries, local configuration, and the configured Ollama service are trusted. Target repository files, comments, paths, tool reports, and LLM responses are untrusted. A malicious same-user process, compromised scanner runtime, browser extension with local access, or root attacker is outside the current containment guarantee.

This is an application-level boundary, **not a hardened sandbox**. Use an isolated VM/container with OS-enforced limits and blocked egress for truly hostile repositories. A container alone is not a proof of sandbox safety.

## Implemented controls and remaining exposure

| Threat | Current control | Residual limitation |
| --- | --- | --- |
| Target executes a lifecycle script | No package installation or target code execution | Parser/scanner vulnerabilities are still possible |
| Model reads arbitrary files | Validated exact paths from the captured snapshot; bounded source tool | Model may misunderstand authorized content |
| Prompt injection in source/comments | Treat as data, no shell/write/network tools, structured response validation, evidence-ID allowlist | Prompts alone cannot eliminate instruction-following attacks or misclassification |
| Secret leakage | Excluded sensitive files, best-effort redaction, Gitleaks raw matches discarded, no tracing | Unknown credential formats and sensitive business logic can remain in excerpts |
| Path traversal / symlinks | Canonical root, relative path checks, containment checks, skipped symlinks, leaf `O_NOFOLLOW` where supported | Concurrent replacement of intermediate directories is not fully isolated |
| CSRF / DNS rebinding | Loopback bind, exact Host/URL/Origin policy, custom mutation header, JSON requirement | No user authentication; not suitable for LAN/public exposure |
| Scan resource exhaustion | Snapshot caps, depth/entry limits, subprocess output/time limits, model iteration/deadline budgets | Directory enumeration and trusted parsers are not OS memory/CPU sandboxed |
| Dirty or stale evidence | Snapshot digests and read-before-resume comparison | Collection is not atomic across files; rules/config/code upgrades require a fresh audit |
| Report/script injection | React escaping, escaped standalone HTML with no scripts/network and restrictive CSP | Markdown must be treated as untrusted input by any third-party renderer |
| Accidental remote transmission | No cloud adapter, disabled remote tracing, no remote fonts, scanner metrics/version checks disabled | Trusted binaries/daemon configuration and OS outbound access remain operator responsibilities |
| Crash with raw scanner staging | Private staging directories, cleanup in normal `finally` path | SIGKILL/power loss can leave plaintext staged source; clean private temp storage after stopping worker |
| Concurrent jobs/reviews | SQLite transactions, one active audit per project, one worker PID lock, explicit state transitions | No distributed lease, row-level tenant isolation, or multi-host coordination |
| False certainty | Candidates, assessments, coverage, and human decisions are separate | Human confirmation can also be mistaken; no guarantee of exploitability or safety |

## Data lifecycle

`.traceward/application.sqlite` stores projects, reports, queue state, review notes, and progress events. `.traceward/checkpoints.sqlite` stores graph state, including redacted evidence excerpts. WAL/SHM files may be created. Files are local and are **not encrypted at rest** by the application. Use encrypted local storage as appropriate.

`.traceward/temporary` can contain raw selected source while external scanners run. Never upload it. Stop the worker before deleting stale staging contents or resetting storage. Remove the entire configured data directory to reset this single-user preview; secure erasure and selective retention are not implemented.

Exports contain source-derived data and are private by default. Check them before sharing. Do not assume redaction is a data-loss-prevention guarantee.

## Security review scope

The initial product does not test live applications, exploit endpoints, validate credential activity, search Git history, prove tenant isolation, establish compliance, certify software, or scan repositories without authorization. Its UI must never suggest otherwise.
