# Portable suppression ledger

Suppressions are explicit review records, not deleted findings. Create one from a static report:

```bash
traceward suppress traceward-report/<audit-id> <finding-id> \
  --owner "Security team" \
  --justification "Accepted during the bounded migration window." \
  --evidence "Change record CR-123 documents the compensating control." \
  --expires-at 2026-12-31T23:59:59Z
```

This writes `suppression-ledger.json` beside the report by default. Apply it only when explicitly
running a fresh audit:

```bash
traceward audit . --suppressions suppression-ledger.json --policy balanced
```

An entry applies only when all of these still match:

- project name;
- finding fingerprint and rule ID;
- exact evidence paths;
- every source-file digest;
- expiry evaluated at the new audit timestamp.

The report keeps counts for applied, stale, expired, and unmatched entries. Active entries retain
owner, justification, supporting evidence, creation/expiry, source, and exact target. They remain in
the report and agent bundle; they do not change scanner coverage or erase evidence.

The static output publishes `suppression-ledger.schema.json`. Invalid, oversized, cross-project,
path-traversal-shaped, weakly justified, or expired entries fail closed or remain unapplied. Owner
identity is not authenticated in this local release, so the report states that limitation.
