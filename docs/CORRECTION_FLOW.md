# Bounded correction evidence

CodebaseScan audits source but never edits a target project or runs its scripts. A separately
authorized coding agent can correct one task and return a strict external verification ledger.
CodebaseScan then validates that ledger against the deterministic baseline plan and a fresh after
audit.

## Flow

1. Keep the original report directory as the baseline.
2. Export one bounded task with `codebasescan task` and authorize the intended change separately.
3. Let the coding agent change only allowed paths and commit one coherent correction.
4. Run only test and build scripts declared in inert root `codebasescan.config.json` project context.
5. Record each command as arguments, exit code, duration, output byte count, and SHA-256. Do not
   retain raw output in the ledger.
6. Run a fresh CodebaseScan audit without the ledger.
7. Create `verification-ledger.json`, binding it to both reports and the baseline plan digest.
8. Generate the immutable combined report with `codebasescan finalize`.

```bash
codebasescan audit . --report-dir codebasescan-after
codebasescan finalize codebasescan-after/<after-id>/audit-report.json \
  --baseline codebasescan-before/<before-id>/audit-report.json \
  --verification verification-ledger.json \
  --report-dir codebasescan-final
```

The baseline plan digest is the `sha256` for `agent-plan.json` in the baseline
`run-manifest.json`. The finalized directory preserves the supplied ledger, its JSON Schema, the
remediation result, and the remediation-result JSON Schema.

## Ledger contract

```json
{
  "schemaVersion": 1,
  "kind": "codebasescan-verification-ledger",
  "createdAt": "2026-09-10T12:00:00.000Z",
  "project": {
    "name": "example",
    "before": {
      "auditId": "<baseline-audit-id>",
      "snapshotDigest": "<baseline-snapshot-sha256>"
    },
    "after": {
      "auditId": "<after-audit-id>",
      "snapshotDigest": "<after-snapshot-sha256>"
    }
  },
  "planDigest": "<agent-plan-artifact-sha256>",
  "executions": [
    {
      "id": "execution-0123456789abcdef",
      "kind": "project_test",
      "argv": ["pnpm", "run", "test"],
      "workingDirectory": "project_root",
      "startedAt": "2026-09-10T11:00:00.000Z",
      "durationMs": 12000,
      "exitCode": 0,
      "outputSha256": "<captured-output-sha256>",
      "outputBytes": 4096,
      "outputTruncated": false,
      "executor": "authorized-coding-agent",
      "network": "denied"
    }
  ]
}
```

Only exact `project_test` and `project_build` argument arrays already present in the baseline plan
are applied. Unknown commands stay visible as unmatched. A failed command makes its acceptance
check fail; missing evidence leaves it `not_run`; a resolved lifecycle with incomplete declared
verification remains partial.

The ledger is provenance, not proof. CodebaseScan checks project, audit, snapshot, plan, and command
identity, but does not authenticate the executor or prove that the recorded process produced the
claimed output digest. Signed executor identities and source-control diff attestations remain
future hardening.
