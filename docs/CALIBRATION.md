# Real-project calibration

CodebaseScan keeps detector output separate from reviewer ground truth. A finding is a candidate
until a reviewer records an outcome against the exact audit snapshot and evidence digests.

Calibration supports four outcomes:

- `true_positive` — the candidate describes a real issue within the rule's declared scope;
- `false_positive` — the rule matched, but the claimed issue is not present;
- `not_applicable` — the rule does not apply to this project or source boundary;
- `inconclusive` — the available source evidence cannot settle the candidate.

Each review also rates the evidence, file/line location, and human explanation. Manual misses are
recorded separately so precision cannot be presented as recall.

## Review one audit

The ledger is a sidecar beside the immutable audit directory. It does not modify
`audit-report.json` or the human disposition ledger.

```bash
codebasescan calibration review \
  codebasescan-report/<audit-id>/audit-report.json \
  <finding-id> true_positive \
  --reviewer reviewer-a \
  --note "Confirmed against the cited source and its mapped caller." \
  --evidence correct \
  --location correct \
  --explanation clear
```

Record a manually found supported issue that the scan missed:

```bash
codebasescan calibration miss \
  codebasescan-report/<audit-id>/audit-report.json \
  --file src/path/to/file.ts \
  --line 42 \
  --expected-rule TW-AST004 \
  --reviewer reviewer-a \
  --note "Manual source review found a request-to-sink path not reported."
```

Declare review completeness only after the stated work was actually performed:

```bash
codebasescan calibration scope \
  codebasescan-report/<audit-id>/audit-report.json \
  --candidates complete \
  --false-negatives sampled \
  --reviewer reviewer-a \
  --note "All candidates were reviewed; false-negative review sampled API routes."
```

## Aggregate multiple projects

```bash
codebasescan evaluate \
  project-a/codebasescan-report/<audit-id>/audit-report.json \
  project-b/codebasescan-report/<audit-id>/audit-report.json \
  --artifacts \
  --output calibration-report.json
```

Sidecar ledgers are discovered automatically. The aggregate replaces project names with `P01`,
`P02`, and so on, and never copies raw source. It reports sample precision only for decided
candidate reviews. Reviewed recall appears only when every project declares a complete
false-negative review. `accuracyClaimReady` remains false until all candidates and false-negative
scope are complete and no candidate is inconclusive.

Synthetic fixture metrics and real-project calibration answer different questions. Fixture
benchmarks protect rule regressions. Real-project review measures usefulness on captured repository
shapes. Neither is a security certification.
