# CodebaseScan

**Audit coverage for JavaScript codebases.**

[Demo](https://andrewsrigom.github.io/codebasescan/) ·
[npm](https://www.npmjs.com/package/codebasescan) ·
[Documentation](docs/README.md)

CodebaseScan turns an authorized Node.js, React, or Next.js repository into a coverage-style audit
report. It inspects source, manifests, lockfiles, and declarative configuration without running the
target application or sending source code to a model.

The result is useful in three places:

- a human-readable static dashboard for triage and sharing;
- versioned JSON, SARIF, CycloneDX, and policy artifacts for automation and CI;
- bounded rules and work plans that a separately authorized coding agent can consume.

The report records what ran, what failed, what was unsupported, and what still requires manual
evidence. Zero findings never means “proven safe.”

> Requires Node.js 22.16+. Linux CI is the release gate; native Windows CLI and package smoke
> checks also pass.

## What it checks

A default audit runs nine offline modes:

- application and framework security;
- SaaS controls such as tenant scope, billing input, tokens, webhooks, and error exposure;
- Next.js routes, caching, responses, and React server/client boundaries;
- dependency advisories, lockfiles, package integrity, and supply-chain posture;
- dependency structure, duplicate code, dead code, complexity, and imported test coverage;
- static accessibility checks and optional imported Axe results;
- privacy and reliability patterns;
- release-readiness and environment-contract gaps;
- web discovery and SEO posture, including robots, sitemap, metadata, and optional `llms.txt`.

Rules combine TypeScript parsing, bounded call relationships, framework semantics, and conservative
heuristics. Findings are candidates for review—not proof of exploitability.

## Quick start

Install it as a project-local development dependency so the audit version is reproducible:

```bash
npm install --save-dev codebasescan
npx codebasescan init
npx codebasescan doctor
npx codebasescan audit . --open
```

The command updates `codebasescan-report/` with the current result. Open
`codebasescan-report/index.html` directly, use the loopback report server, or host the complete
directory as static files after reviewing it for sensitive source evidence.

Global installation also works, but a local development dependency is recommended for teams and CI.

## Review with your own coding agent

CodebaseScan does not embed a model runtime. Scan deterministically first, then let the coding agent
the user already trusts inspect the evidence and repository under separate authorization.

For Codex:

```bash
npx codebasescan agent install codex .
```

This writes three repo-scoped skills under `.agents/skills/`: `codebasescan-review` for one finding,
`codebasescan-gap-review` for questions the scanner could not settle, and
`codebasescan-verify-fix` for an explicitly authorized before/after check. They use the verified
report and keep new hypotheses separate from deterministic findings.

The same evidence is readable from the terminal without loading the whole report:

```bash
npx codebasescan report verify codebasescan-report
npx codebasescan findings list codebasescan-report --limit 20
npx codebasescan finding show codebasescan-report <finding-id>
npx codebasescan coverage show codebasescan-report
```

Other agents can consume the same versioned JSON and schemas. They should never silently rewrite,
downgrade, suppress, or confirm scanner evidence.

pnpm and Yarn installations are also tested. CodebaseScan installs its own dependencies; an audit
never installs the target project's dependencies or runs its scripts, configuration modules, tests,
build, or application code.

To reopen the current report later:

```bash
codebasescan open codebasescan-report
```

You can also open `codebasescan-report/index.html` directly or host the complete
`codebasescan-report/` directory as a static site. Review the files before hosting them because
paths, excerpts, and project metadata may be sensitive.

## One current report

Each run safely updates one portable report directory instead of accumulating product-managed
history. It contains:

- `index.html` — script-free human dashboard;
- `audit-report.json` — complete machine-readable result;
- `run-manifest.json` and `manifest.json` — coverage, versions, limits, hashes, and integrity;
- `policy-result.json` — CI decision and exit-code evidence;
- `agent-context.json`, `agent-report.json`, `agent-rules.json`, and `agent-plan.json` — external-agent contracts;
- `report.sarif`, `report.md`, and `sbom.cdx.json` — portable integration formats;
- JSON Schemas for generated workflow artifacts.

CodebaseScan removes stale managed artifacts when the current audit no longer produces them and
refuses to overwrite a nonempty directory it does not recognize. If history is required, preserve
the directory as a CI artifact or copy `audit-report.json` before the next run.

Detector quality is reviewed through a separate calibration ledger, so scanner output never
becomes its own ground truth. See [real-project calibration](docs/CALIBRATION.md).

Preserve a report before remediation when you want a before/after view:

```bash
cp codebasescan-report/audit-report.json codebasescan-baseline.json
npx codebasescan audit . --baseline codebasescan-baseline.json
```

For an agent-readable comparison with integrity checks, preserve the complete before report
directory as `codebasescan-before/`, run the audit again, then inspect:

```bash
codebasescan changes show codebasescan-before codebasescan-report
```

This shows new candidates and coverage regressions. An absent candidate is not proof of a fix.

## Focused audits

All modes run by default. Select a smaller set when needed:

```bash
codebasescan audit . --modes security,saas,next-react
codebasescan audit . --modes accessibility-static,privacy,reliability,web-posture
```

Modes that were not selected remain visible as disabled coverage.

## Project context

A root `codebasescan.config.json` or JSONC file can declare project vocabulary without executing code:

```json
{
  "schemaVersion": 1,
  "vocabulary": {
    "tenantKeys": ["workspaceId"],
    "roleKeys": ["membershipRole"]
  },
  "helpers": {
    "authorization": ["requireMembership"],
    "resourceScope": ["scopeToWorkspace"],
    "rateLimit": ["consumeQuota"],
    "idempotency": ["claimDelivery"]
  },
  "expectedUnauthenticatedRoutes": ["/api/health", "/api/public/*"],
  "context": {
    "features": ["authentication", "tenancy", "billing"],
    "sensitiveData": ["personal", "financial"],
    "externalServices": ["stripe"],
    "authenticationMethods": ["cookie"],
    "deploymentModel": "embedded",
    "trustedParentOrigins": ["https://parent.example.com"],
    "tenantIsolation": ["application"]
  }
}
```

These are project declarations for focused review, not verified runtime controls. Only exact origins
without paths, credentials, or query strings are accepted; no declared origin is probed by default.

JavaScript and TypeScript configuration files from the target repository are never imported. Lifecycle scripts, builds, tests, and application code are not executed.

## Optional scanners and network access

Semgrep and Gitleaks can add local scanner evidence. OSV can refresh a compact advisory cache. Every integration is opt-in:

```dotenv
CODEBASESCAN_SEMGREP=true
CODEBASESCAN_GITLEAKS=true
CODEBASESCAN_OSV=true
```

The scanner binaries must already be installed and trusted. OSV receives package names and exact
resolved versions only. A normal audit does not call a model or require an API key.

To check effective HTTP headers for known routes, pass each URL explicitly (up to three). The probe
uses bounded HEAD/GET, validates DNS and redirects, and keeps no cookie values or form inputs:

```bash
codebasescan audit . --probe-url https://app.example.com/ --probe-url https://app.example.com/login
```

This does not crawl, log in, or prove that untested routes have the same headers.

For browser accessibility evidence, generate a standard Axe JSON result outside CodebaseScan and
place it at the project root as `codebasescan.axe.json`, `axe-results.json`, or
`axe-report.json`. CodebaseScan imports bounded violation groups but does not launch the target
application or a browser. Without that artifact, runtime accessibility is explicitly
`NOT PERFORMED`.

## CI

Use the bundled GitHub Action to keep full repository context while blocking only findings added by
a pull request:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: andrewsrigom/codebasescan@v0.4.0
  with:
    policy: balanced
    baseline-ref: ${{ github.event.pull_request.base.sha }}
```

The action uploads the static report and SARIF before applying the policy exit code. See the
[complete CI setup](docs/CI.md), including required permissions and fork behavior.

The direct CLI gate is:

```bash
codebasescan audit . --policy balanced
```

Exit codes:

- `0` — audit completed and the selected policy passed;
- `1` — findings failed the selected policy;
- `2` — coverage or audit execution blocked the result.

A passing policy is not a security certification.

## Repository development UI

The source repository also contains a local Next.js review application used to develop and inspect
the same domain contracts:

```bash
cp .env.example .env.local
npm run demo
npm run dev
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000). Run `npm run worker` in a second terminal for queued audits.

The application uses TypeScript, Tailwind CSS, and shadcn primitives. The portable report has a separate script-free renderer so it does not depend on the application server.

## Safety boundaries

Only audit code you own or are authorized to assess.

CodebaseScan does not:

- execute the target repository;
- install its dependencies;
- run its scripts, tests, or builds;
- crawl or exploit a deployed application;
- claim compliance or complete security coverage.

See the [security policy](SECURITY.md) and [threat model](docs/THREAT_MODEL.md) before using it on sensitive repositories.

## Development

```bash
git clone https://github.com/andrewsrigom/codebasescan.git
cd codebasescan
npm ci
npm run format:check
npm run typecheck
npm run lint
npm test
npm run test:integration
npm run benchmark
npm run build
npm run test:e2e
npm run test:package
```

Useful references:

- [Architecture](docs/ARCHITECTURE.md)
- [Validation](docs/VALIDATION.md)
- [Continuous integration](docs/CI.md)
- [Real-project calibration](docs/CALIBRATION.md)
- [Engineering decisions](docs/DECISIONS.md)
- [Roadmap](docs/ROADMAP.md)
- [Releasing](docs/RELEASING.md)
- [Documentation index](docs/README.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

MIT. External scanners, rules, and dependencies retain their own licenses and terms.
