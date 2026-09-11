# CodebaseScan

CodebaseScan audits Node.js, React, and Next.js repositories from the command line. One command turns source code, package metadata, lockfiles, and inert configuration into a static human report plus structured evidence for automation and AI-assisted investigation.

[View demo](https://andrewsrigom.github.io/codebasescan/). The page shows the evidence, coverage, and prioritized review work produced by a real audit. Findings remain review candidates, not a certification.

I built it for a common situation: the repository is available, but production logs and telemetry are not. The tool starts with source code, package metadata, lockfiles, and inert configuration. It does not run the project being audited, and AI is not required.

> CodebaseScan is under active development. WSL2/Linux and Node.js 22.16+ are the tested environment today.

## What it checks

A default audit runs nine offline modes:

- application and framework security;
- SaaS controls such as tenant scope, billing input, tokens, webhooks, and error exposure;
- Next.js and React boundaries;
- dependencies, lockfiles, package integrity, and supply-chain posture;
- maintainability, duplicate code, dependency structure, and dead code;
- static accessibility checks;
- privacy-related source patterns;
- reliability and release-readiness gaps;
- web discovery and SEO posture, including robots, sitemap, Next.js metadata, and optional llms.txt presence.

Findings are review candidates, not proof that a vulnerability is exploitable. Coverage is part of the result, so a scanner failure or unsupported area cannot look like a clean audit.

## Install

The intended installation is a project-local development dependency:

```bash
npm install --save-dev codebasescan
npx codebasescan init
npx codebasescan doctor
npx codebasescan audit .
```

To let Codex investigate the generated evidence with the bundled review rules:

```bash
npx codebasescan agent install codex .
```

This writes `.codex/skills/codebasescan-review` in the target project. The skill verifies the
report package, inspects relevant repository context, challenges false positives, and keeps any
new AI hypothesis separate from deterministic findings.

pnpm and Yarn installations are also tested. Package dependencies install with CodebaseScan; the
target project's dependencies, scripts, configuration modules, tests, and application code are
never installed or executed by an audit. The persistent review application and local Ollama adapter
use optional peer dependencies and are not required for the terminal report.

The public package is [available on npm](https://www.npmjs.com/package/codebasescan). To develop or
test the repository build directly:

```bash
git clone https://github.com/andrewsrigom/codebasescan.git
cd codebasescan
npm ci
npm run build:cli
npm link
```

Then run `codebasescan init`, `codebasescan doctor`, and `codebasescan audit .` inside the
repository you want to inspect. The audit stays local. Add `--open` to start a loopback-only
server for the generated report; stop it with Ctrl+C.

To reopen the report history later:

```bash
codebasescan open codebasescan-report
```

You can also open `codebasescan-report/index.html` directly or host the complete
`codebasescan-report/` directory as a static site. The stable root always points to the newest
audit and lists immutable earlier audit directories. Review the files before hosting them because
paths, excerpts, and project metadata may be sensitive.

## Report files

Each run creates one immutable directory under `codebasescan-report/`. The root contains:

- `index.html` — stable latest-and-history view;
- `report-index.json` — versioned machine-readable history.

Each immutable audit directory contains:

- `index.html` — human-readable report;
- `audit-report.json` — complete machine-readable result;
- `agent-plan.json` — grouped work queue for an authorized coding agent;
- `agent-report.json` — complete review workflow, depths, tasks, and rule references for AI;
- `agent-rules.json` — versioned evidence questions and false-positive checks;
- `run-manifest.json` — scanner status, coverage, versions, limits, and artifact hashes;
- `policy-result.json` — optional CI policy result;
- SARIF, Markdown, CycloneDX, schemas, and a hash manifest.

Detector quality is reviewed through a separate calibration ledger, so scanner output never
becomes its own ground truth. See [real-project calibration](docs/CALIBRATION.md).

A new audit gets a new ID. Use an earlier JSON report as a baseline when you want a before/after view:

```bash
codebasescan audit . \
  --baseline codebasescan-report/<previous-audit-id>/audit-report.json
```

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

An optional model investigation layer also exists, but it is off by default and is not needed for
the mechanical audit. There is no automatic local-to-cloud fallback.

```dotenv
CODEBASESCAN_AI=openai
OPENAI_MODEL=<model>
OPENAI_API_KEY=<key>
CODEBASESCAN_AI_DEPTH=standard
```

Use `quick` for report-focused triage, `standard` for related source and bounded snapshot
search, or `deep` for broader cross-file investigation. Deep review has higher explicit context,
call, and token limits. Local Ollama uses the same structured reviewer contract with
`CODEBASESCAN_AI=ollama` and `OLLAMA_MODEL=<downloaded-model>`.

LangGraph owns the repeatable collect, assess, challenge, and stop decisions, including checkpoint
compatibility. LangChain provides the structured model interface for the optional local adapter.
The built-in workflow searches only the captured immutable snapshot; the installed Codex skill can
inspect the authorized repository directly while following the same rules and evidence contract.

For browser accessibility evidence, generate a standard Axe JSON result outside CodebaseScan and
place it at the project root as `codebasescan.axe.json`, `axe-results.json`, or
`axe-report.json`. CodebaseScan imports bounded violation groups but does not launch the target
application or a browser. Without that artifact, runtime accessibility is explicitly
`NOT PERFORMED`.

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
- [Real-project calibration](docs/CALIBRATION.md)
- [Engineering decisions](docs/DECISIONS.md)
- [Roadmap](docs/ROADMAP.md)
- [Releasing](docs/RELEASING.md)
- [Documentation index](docs/README.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

MIT. External scanners, APIs, models, rules, and dependencies retain their own licenses and terms.
