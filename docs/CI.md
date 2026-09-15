# Continuous integration

The repository ships a composite GitHub Action. It scans the complete repository so cross-file
authorization and data-flow evidence remain available, then uses a baseline to gate only findings
introduced by the pull request. This is safer than parsing changed files in isolation and does not
hide existing findings from the uploaded report.

```yaml
name: Codebase audit
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  codebasescan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: andrewsrigom/codebasescan@v0.4.0
        with:
          policy: balanced
          baseline-ref: ${{ github.event.pull_request.base.sha }}
```

For a push without a pull-request base, omit `baseline-ref`. The action uploads the complete static
report and SARIF by default. Set `upload-sarif: false` when the workflow cannot receive
`security-events: write`, such as an untrusted fork.

Policies are deterministic:

- `advisory` reports without blocking on findings;
- `balanced` blocks new high-confidence high or critical candidates when a baseline is supplied;
- `strict` evaluates all current debt and stricter coverage requirements.

The action returns CodebaseScan's exit code after artifact upload: `0` passed, `1` policy findings,
and `2` incomplete blocking coverage or execution. Semgrep and Gitleaks remain opt-in and must
already exist on the runner's `PATH`. Each tagged Action installs and verifies the matching exact
CodebaseScan npm version; the repository smoke test uses the latest already-published version until
the release candidate itself is published.
