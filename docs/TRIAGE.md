# Project-local triage memory

CodebaseScan keeps deterministic findings and later assessments separate. An external agent may
record an evidence-backed, provisional assessment without changing the scanner result:

```bash
codebasescan triage record codebasescan-report <finding-id> likely_false_positive \
  --evidence <evidence-id> \
  --note "The reported path is unreachable from the declared public entry point."
codebasescan triage list codebasescan-report --json
```

The default sidecar is `codebasescan-report.triage-ledger.json` beside, not inside, the report
directory. It belongs to one project and is not included in the public static report. It stores
the finding fingerprint, rule, cited evidence IDs, source-file digests, source audit, assessment,
and redacted rationale. The assessment is one of `likely_valid`, `likely_false_positive`, or
`inconclusive`; it is not an authenticated human verdict.

On a fresh report, `triage list` labels exact matches `current`, changed evidence `stale`, and
absent findings `unmatched`. Stale and unmatched notes remain readable but never auto-apply.
Triage does not change findings, severity, coverage, policy, or SARIF. Agents may use a current note
to avoid repeating context gathering, but must verify the cited evidence before relying on it.

If the same codebase is audited from a differently named Git worktree, the report project name
changes. Transfer only assessments whose fingerprint, rule, cited evidence IDs, and source-file
digests still match both reports:

```bash
codebasescan triage transfer old-report new-report
codebasescan triage list new-report --json
```

The command verifies both static report packages, reads the old private sidecar, writes a new
private sidecar beside `new-report`, and
refuses to overwrite an existing one. Stale or absent entries stay only in the old ledger. It
requires an explicit source and target report; it never treats an agent assessment as a human
confirmation or changes the scan result.

When the report is in WSL, run the CLI inside WSL for private sidecar writes. Windows cannot
enforce `0600` permissions through `\\wsl.localhost` or `\\wsl$`; those destinations are refused
instead of silently creating a world-readable ledger. Reading verified reports via UNC remains
supported.

Human-confirmed decisions use the existing, separate review ledger:

```bash
codebasescan review codebasescan-report <finding-id> false_positive \
  --note "Verified against the owner-approved runtime control."
codebasescan audit . --reviews codebasescan-report.review-ledger.json
```

The review ledger now defaults beside the report directory as well. Review import remains explicit.
An old `review-ledger.json` inside a report is read when the next decision is recorded and copied
to the new sidecar; the old file is not deleted. Exclude old sidecars before hosting a static report.
Even applied human decisions retain the original finding and require matching fingerprint and
source-file digests. Changed source must be reviewed again.
