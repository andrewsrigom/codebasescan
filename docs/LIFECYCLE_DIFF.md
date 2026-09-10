# Finding lifecycle diff

Traceward comparison schema version 3 compares two immutable audit reports and, when available,
earlier reports from the same local project.

## States

- new: lifecycle identity exists in current but not base;
- resolved: lifecycle identity exists in base but not current;
- unchanged: lifecycle identity exists in both;
- reappeared: lifecycle identity is new relative to base and exists in an explicitly supplied earlier
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

## Identity and migration

Schema version 3 uses source, advisory ID, package, resolved version, and lockfile for dependency
advisories. This prevents a lockfile line shift from inventing resolved and new advisories. Other
findings retain the exact fingerprint as lifecycle identity. A dependency version change remains a
real lifecycle change, even when the same advisory affects both versions.

Version 2 consumers may keep reading old comparison files, but must not merge their counts with
version 3 because the identity semantics differ. Remediation-result schema version 2 uses the same
lifecycle identity. Version 1 results remain immutable historical artifacts and are not rewritten.

Resolved means absent from the current report, not verified remediation. A source-line move for a
non-dependency finding can still appear as one resolved and one new finding. Reappeared requires
the exact prior lifecycle identity and is not inferred from similar titles or rules.
