# Traceward

Local-first security review for TypeScript, Node.js, and Next.js repositories.

Traceward turns source code into review candidates with evidence, coverage gaps, and a human decision trail. It does not execute the target repository and does not require AI.

**Status:** usable local workflow, validated on WSL2/Linux. Apache-2.0. Node.js 22.16+.

![Traceward audit workspace](docs/assets/workspace.png)

## Why Traceward

Most small teams have code but little production telemetry. Traceward starts with what is available:

- framework-aware source rules and project mapping;
- bundled dependency-cycle, coupling, orphan-module, and duplicate-code reports;
- security checklist with explicit unknowns and gaps;
- optional Semgrep, Gitleaks, OSV, and one approved HTTP observation;
- optional Ollama or OpenAI investigation with hard limits;
- human review before publication;
- HTML, Markdown, JSON, SARIF, and bounded Codex exports.

Findings are candidates, not proof of exploitability. Missing coverage never becomes a clean result.

## Quick start

WSL2/Linux is the primary tested environment.

```bash
npm ci
cp .env.example .env.local
npm run cli -- doctor
npm run demo
npm run dev
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000).

For queued audits, run the worker in another terminal:

```bash
npm run worker
```

## Audit a repository

Only inspect code you own or are authorized to assess.

```bash
npm run cli -- register /absolute/path/to/project
npm run cli -- scan /absolute/path/to/project
npm run cli -- list
npm run cli -- export <audit-id> html
```

Traceward captures a bounded snapshot. It never installs dependencies, runs lifecycle scripts, starts the target app, or exploits it.

Dependency structure and duplication analysis run offline by default with pinned Traceward-owned tools. Target `dependency-cruiser`, `jscpd`, TypeScript, Babel, ESLint, and framework configuration files are not loaded or executed. Mechanical results are maintainability evidence, not vulnerabilities.

Every finding keeps detector confidence, probable exposure, a 0–100 review priority, and human disposition separate. Reviewers can mark findings confirmed, fixed, false positive, accepted risk, or still needing review. Project exceptions require a reason, may expire, never delete evidence, and can be removed. A completed audit can be selected as the project comparison baseline.

## Optional depth

External scanners stay opt-in:

```dotenv
TRACEWARD_SEMGREP=true
TRACEWARD_GITLEAKS=true
TRACEWARD_OSV=true
```

Semgrep and Gitleaks must be trusted local binaries. OSV receives only resolved npm package names and versions.

Current-source secret scanning classifies test/example matches separately. Git history is scanned only when explicitly selected for an audit:

```bash
npm run cli -- audit /absolute/path/to/project --secret-history
```

Historical findings retain only file, line, rule, and commit metadata. Raw matched values are discarded.

Dependency inventory and local advisory matching work offline. Refresh the compact database for a project manually when network access is allowed:

```bash
npm run cli -- advisories update /absolute/path/to/project
```

Future audits use the saved exact-version records without a network request. Dependency findings distinguish direct/transitive relationships, source-reference reachability, fixed versions, and unknown exploitability. Reports can be exported as CycloneDX 1.6 SBOMs.

AI is optional and never receives an arbitrary filesystem tool:

```dotenv
TRACEWARD_AI=ollama
OLLAMA_MODEL=your-downloaded-model
```

For OpenAI, use [.env.example](.env.example). Requests use structured output, redaction, timeouts, cache, hard budgets, and store disabled. There is no automatic local-to-cloud fallback.

To investigate manually with Codex without enabling OpenAI in Traceward:

```bash
npm run cli -- export <audit-id> bundle
```

Attach the generated bundle to an authorized Codex task. It contains bounded evidence and opaque IDs, not the registered project root.

## CI

```bash
npm run cli -- audit . --ci --fail-on high --format sarif --output traceward.sarif
```

Exit 0: gate passed. Exit 1: unresolved findings reached the threshold. Exit 2: audit failed operationally.

Use --baseline report.json to gate only newly introduced findings. A passing gate is not a security certification.

## What is intentionally out of scope

- whole-program taint or dependency reachability proof;
- broad crawling, exploitation, or pentesting;
- cloud IAM, infrastructure-as-code, compliance certification, or hosted multi-user operation.

The supported deployment is one trusted OS user, a loopback-only UI, one local worker, and authorized repositories.

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
```

Start with [Contributing](CONTRIBUTING.md) and the [Code of conduct](CODE_OF_CONDUCT.md). Security boundaries are in [Security policy](SECURITY.md) and [Threat model](docs/THREAT_MODEL.md).

## Documentation

- [Documentation index](docs/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Validation](docs/VALIDATION.md)
- [Real-project evaluation](docs/REAL_PROJECT_EVALUATION.md)
- [Roadmap](docs/ROADMAP.md)
- [Changelog](CHANGELOG.md)

## License

Apache-2.0. External scanners, APIs, models, rules, and dependencies retain their own licenses and terms. Traceward is a working name; domain and trademark availability have not been checked.
