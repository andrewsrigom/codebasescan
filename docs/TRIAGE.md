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
