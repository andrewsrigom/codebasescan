# CodebaseScan

CodebaseScan audits Node.js, React, and Next.js repositories from the command line and produces a static report you can keep, compare, or host.

I built it for a common situation: the repository is available, but production logs and telemetry are not. The tool starts with source code, package metadata, lockfiles, and inert configuration. It does not run the project being audited, and AI is not required.

> CodebaseScan is under active development. WSL2/Linux and Node.js 22.16+ are the tested environment today.

## What it checks

A default audit runs eight offline modes:

- application and framework security;
- SaaS controls such as tenant scope, billing input, tokens, webhooks, and error exposure;
- Next.js and React boundaries;
- dependencies, lockfiles, package integrity, and supply-chain posture;
- maintainability, duplicate code, dependency structure, and dead code;
- static accessibility checks;
- privacy-related source patterns;
- reliability and release-readiness gaps.

Findings are review candidates, not proof that a vulnerability is exploitable. Coverage is part of the result, so a scanner failure or unsupported area cannot look like a clean audit.

## Try it from source

CodebaseScan is not published to npm yet.

```bash
git clone https://github.com/andrewsrigom/codebasescan.git
cd codebasescan
npm ci
npm run build:cli
npm link
codebasescan doctor
```

Run it from the repository you want to inspect:

```bash
cd /path/to/project
codebasescan audit . --open
```

The audit stays local. `--open` starts a loopback-only server for the generated report. Stop it with Ctrl+C.

To reopen the newest report later:

```bash
codebasescan open codebasescan-report
```

You can also open `codebasescan-report/<audit-id>/index.html` directly or publish the whole audit directory as a static site. Review the report before hosting it because file paths and project metadata may be sensitive.

## Report files

Each run creates one immutable directory under `codebasescan-report/`. The main files are:

- `index.html` — human-readable report;
- `audit-report.json` — complete machine-readable result;
- `agent-plan.json` — grouped work queue for an authorized coding agent;
- `run-manifest.json` — scanner status, coverage, versions, limits, and artifact hashes;
- `policy-result.json` — optional CI policy result;
- SARIF, Markdown, CycloneDX, schemas, and a hash manifest.

A new audit gets a new ID. Use an earlier JSON report as a baseline when you want a before/after view:

```bash
codebasescan audit . \
  --baseline codebasescan-report/<previous-audit-id>/audit-report.json
```

## Focused audits

All modes run by default. Select a smaller set when needed:

```bash
codebasescan audit . --modes security,saas,next-react
codebasescan audit . --modes accessibility-static,privacy,reliability
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
    "externalServices": ["stripe"]
  }
}
```

JavaScript and TypeScript configuration files from the target repository are never imported. Lifecycle scripts, builds, tests, and application code are not executed.

## Optional scanners and network access

Semgrep and Gitleaks can add local scanner evidence. OSV can refresh a compact advisory cache. Every integration is opt-in:

```dotenv
CODEBASESCAN_SEMGREP=true
CODEBASESCAN_GITLEAKS=true
CODEBASESCAN_OSV=true
```

The scanner binaries must already be installed and trusted. OSV receives package names and exact resolved versions only.

An optional model investigation layer also exists, but it is off by default and is not needed for the mechanical audit. There is no automatic local-to-cloud fallback.

## CI

```bash
codebasescan audit . --policy balanced
```

Exit codes:

- `0` — audit completed and the selected policy passed;
- `1` — findings failed the selected policy;
- `2` — coverage or audit execution blocked the result.

A passing policy is not a security certification.

## Local application

The repository also contains the persistent Next.js review application:

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
npm run format:check
npm run typecheck
npm run lint
npm test
npm run test:graph
npm run benchmark
npm run build
npm run test:e2e
npm run test:package
```

Useful references:

- [Architecture](docs/ARCHITECTURE.md)
- [Validation](docs/VALIDATION.md)
- [Engineering decisions](docs/DECISIONS.md)
- [Roadmap](docs/ROADMAP.md)
- [Documentation index](docs/README.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

MIT. External scanners, APIs, models, rules, and dependencies retain their own licenses and terms.
