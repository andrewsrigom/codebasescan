# Run and coverage manifest

Every static report includes `run-manifest.json` and its Draft 7 JSON Schema. This is the compact
entry point for automation and later AI review before either reads the larger audit report.

The manifest records:

- Traceward, workflow, rule-pack, report, and manifest versions;
- audit and snapshot identity without the repository's absolute path;
- requested/effective audit modes when that selection exists;
- captured files, skipped counts, truncation, and preflight limits;
- every scanner status, duration, version, finding count, and bounded status detail;
- complete, partial, failed, disabled, unsupported, and unperformed coverage separately;
- report limitations and digests for the generated evidence artifacts.

`execution.scannerDurationMs` is the sum of scanner durations, not wall-clock elapsed time. Output
digests cover the evidence artifacts listed by the run manifest. The outer `manifest.json` also
digests `run-manifest.json`, avoiding a circular self-digest.

Consumers must fail closed when the schema is invalid. They must not interpret a partial, failed,
disabled, unsupported, or unperformed capability as a clean result.
