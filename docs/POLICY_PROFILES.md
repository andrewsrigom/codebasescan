# Policy profiles and exit codes

`codebasescan audit` can apply one deterministic policy profile:

```bash
codebasescan audit . --policy advisory
codebasescan audit . --policy balanced
codebasescan audit . --policy strict
```

Every static report publishes `policy-result.json` plus a Draft 7 JSON Schema. With no explicit
profile, the report records `advisory` and does not fail because of findings or coverage.

| Profile  | Finding gate                                                      | Coverage gate                 |
| -------- | ----------------------------------------------------------------- | ----------------------------- |
| advisory | Records eligible findings; never blocks                           | Records gaps; never blocks    |
| balanced | High/critical with medium/high confidence; new-only with baseline | Failed or truncated analysis  |
| strict   | Every unresolved medium/high/critical finding, including old debt | Partial, failed, or truncated |

Fixed, false-positive, accepted-risk, and active suppressed findings do not gate. Suppression
expiry is evaluated against the immutable audit timestamp so replay is deterministic. Disabled,
not-run, unsupported, and unperformed capabilities always remain visible, but built-in profiles do
not require optional runtime or future product capabilities.

Exit codes are stable:

- `0`: advisory result or passing policy;
- `1`: finding policy failed;
- `2`: blocking coverage problem or operational audit failure.

Inspect `policy-result.json` to distinguish incomplete coverage from an operational failure. The
legacy `--fail-on <severity>` gate remains available for compatibility and cannot be combined with
`--policy`.

A passing policy is not a security or compliance certification. It only evaluates the captured
snapshot, deterministic dispositions, active suppressions, and published coverage metadata.
