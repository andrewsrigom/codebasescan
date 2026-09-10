# Finding lifecycle diff

Traceward comparison schema version 2 compares two immutable audit reports and, when available,
earlier reports from the same local project.

## States

- new: fingerprint exists in current but not base;
- resolved: fingerprint exists in base but not current;
- unchanged: fingerprint exists in both;
- reappeared: fingerprint is new relative to base and exists in an explicitly supplied earlier
  report;
- changed: an unchanged fingerprint has different severity, human disposition, or component
  ownership.

Reappeared is empty when no earlier history is supplied. The app and CLI compare command provide
eligible local reports from the same project; the pure domain function accepts history explicitly.

## Component attribution

Finding evidence files first use component IDs already recorded by the project profile. A bounded
nearest-root fallback is used only when a captured component owns the evidence path. Findings with
evidence in multiple components contribute to each component summary. Unmapped evidence remains
visible under Unassigned.

## Limits

The comparison is fingerprint-based and fingerprints include source location. A line move can
therefore appear as one resolved and one new finding. Resolved means absent from the current
report, not verified remediation. Reappeared requires the exact prior fingerprint and is not
inferred from similar titles or rules.
