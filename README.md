# Traceward

**A local-first, evidence-led security review workbench for TypeScript SaaS projects.**

Scanners produce signals. LangGraph coordinates bounded contextual review. Humans make the final disposition.

Traceward combines a Next.js audit UI, a separate TypeScript worker, SQLite persistence, optional local scanners, and optional Ollama inference. It is a portfolio-oriented engineering starter, not a production security product, penetration test, or certification of safety.

> **Delivery status:** the dependency-free core has been exercised locally. The full Next.js / LangGraph integration is written but still requires installation, typechecking, build, and integration/E2E validation. See [Validation](docs/VALIDATION.md) and start with [Codex handoff](docs/CODEX_HANDOFF.md). There is intentionally no fabricated lockfile or passing CI badge.

![Static styling preview, not a validated Next.js runtime screenshot](docs/assets/workspace-styling-preview.png)

*The image is a static styling inspection of the JSX/CSS with inert fixture data. Full runtime validation remains pending. A working standalone [HTML fixture export](examples/fixture-review.html) is also included.*

## Why this project exists

A long list of scanner warnings is not an audit. Developers need to understand what matched, what was inspected, what remains unknown, and whether a human has reviewed the finding. Traceward makes that distinction visible instead of hiding uncertainty behind a security score.

The initial scope is source review for Node.js / TypeScript / Next.js SaaS projects. Framework-level authorization, RLS, deployment configuration, and actual exploitability often require evidence this starter cannot collect. Those gaps remain explicit.

## What is included

| Capability | Initial implementation |
| --- | --- |
| Audit workspace | Overview, searchable findings, evidence drawer, dependency inventory, coverage, workflow, history, project registry, settings, methodology |
| Built-in review | Seven bounded regex heuristics; candidates only, including a deliberate false-positive fixture |
| External scanners | Optional Semgrep and Gitleaks process adapters and JSON normalizers; disabled by default |
| Agent workflow | LangGraph fan-out/fan-in, reducers, a bounded contextual review subgraph, checkpoint persistence, publication interrupt/resume |
| Local inference | Optional Ollama structured assessments; fixed loopback endpoint; source-reading tool limited to the captured snapshot |
| Human review | Explicit disposition and rationale; publishing does not automatically confirm findings |
| Persistence | SQLite application store, separate official LangGraph SQLite checkpointer, single worker, durable job queue |
| Reporting | JSON, Markdown, self-contained HTML, SARIF 2.1.0 |
| Evaluation | Positive, benign, comment-only, and prompt-injection fixtures; unit, graph integration, and browser test suites |

**Not implemented:** OSV/Trivy vulnerability matching, exact resolved dependency inventory, AST/dataflow analysis, real attack-path verification, auto-remediation, Git history scans, multi-user access, remote scanning, cloud LLMs, MCP servers, authentication, billing, or compliance claims.

## Start locally

Use Node.js **22.16 or newer in the Node 22/24 release lines**. WSL2/Linux is the primary target; macOS is a secondary target. Native Windows is not yet validated. Run commands from this repository root.

```bash
npm install
cp .env.example .env.local
npm run demo
npm run dev
```

Open **http://127.0.0.1:3000**. The demonstration scans the included inert fixture through the actual graph with AI and external scanners disabled. It stops at human review. No API key or model download is needed for this mode.

Start the persistent worker in a second terminal **after** the demonstration is seeded:

```bash
npm run worker
```

The UI queues jobs; the worker executes them. Closing the browser does not remove a queued job. Submitting publication review also requires the worker. `npm run demo` deliberately refuses to run alongside an existing worker.

### Review your own repository

Only register repositories you own or have permission to assess. Stop processes that mutate the target while capturing evidence.

```bash
npm run cli -- register /absolute/path/to/my-saas
```

The project then appears in **New audit**. Alternatively:

```bash
npm run cli -- scan /absolute/path/to/my-saas
npm run cli -- list
npm run cli -- export <audit-id> html
```

The target is read-only. Traceward does not run `npm install`, execute its scripts, start its app, or test exploits. Audit storage must not overlap the target; set `TRACEWARD_DATA_DIR` to a separate private directory when scanning Traceward itself.

### Optional local AI

Install Ollama and download an appropriate model separately. Pick a model that supports structured output and fits your available memory; a smaller model is not automatically a reliable security reviewer.

Set these values in `.env.local`:

```dotenv
TRACEWARD_AI=ollama
OLLAMA_MODEL=your-already-downloaded-local-model
```

Configure the **Ollama server process** with `OLLAMA_NO_CLOUD=1`, then restart it. Traceward uses only `http://127.0.0.1:11434` and rejects obvious cloud model names, but an application-level hostname rule is not an operating-system egress sandbox. Block outbound traffic when a strict offline guarantee is required. The app does not download models, enable tracing, or silently fall back to a cloud model.

### Optional scanners

Install trusted Semgrep and/or Gitleaks binaries yourself. Do not install them from the target repository. Then opt in:

```dotenv
TRACEWARD_SEMGREP=true
TRACEWARD_GITLEAKS=true
```

Restart the worker after configuration changes. Both scanners use a bounded temporary snapshot and the trusted configurations in `configs/`. Missing binaries, unsupported output, timeouts, and truncated coverage are not reported as clean scans.

The initial Gitleaks integration scans the current selected source files, **not Git history or excluded `.env` files**. The dependency tab lists declarations in `package.json`; it does **not** prove packages have no known vulnerabilities.

## Development checks

```bash
npm test
npm run benchmark
npm run typecheck
npm run lint
npm run test:graph
npm run build
npx playwright install chromium
npm run test:e2e
```

`npm test` and `npm run benchmark` need only the selected Node runtime, not third-party packages. All other checks need installation first. Commit the real `package-lock.json` generated after resolving and validating dependencies, then use `npm ci` for repeatable installs.

## Project map

```text
src/
  app/          Next.js routes and local HTTP endpoints
  components/   Audit workspace and review controls
  domain/       Evidence, findings, validation, report contracts
  engine/       LangGraph workflow, subgraph, local model adapter
  scanners/     Deterministic patterns and external scanner adapters
  security/     Snapshot boundaries, process limits, redaction, HTTP policy
  server/       SQLite persistence and configuration
  worker/       Durable job consumer, independent from Next.js
  cli/          Explicit project registration, queueing, exports
configs/        Trusted scanner rules; never read from a target repo
fixtures/       Inert labeled review cases, not deployable apps
scripts/        Demo seed and narrow fixture benchmark
tests/          Core, graph integration, and browser suites
docs/           Architecture, threat model, edge cases, portfolio, handoff
```

## Portfolio direction

Demonstrate one evidence-led journey: scan a small repo, inspect a signal, show a benign counterexample, explain the limitation, record human review, export the report. Then show how the graph persists state and resumes after an interrupt. Do not replace this with fabricated benchmark scores or fake AI activity.

Read [Portfolio plan](docs/PORTFOLIO.md), [Architecture](docs/ARCHITECTURE.md), [Threat model](docs/THREAT_MODEL.md), and [Roadmap](docs/ROADMAP.md).

## License and publishing

Apache-2.0 covers this starter's original code. External scanners, models, rules, and dependencies retain their own licenses. No scanner binaries, model weights, font files, or third-party rule packs are bundled. Before redistribution or a commercial release, review the exact components and their licenses.

**Traceward is a working name:** package, domain, and trademark availability have not been checked. Publish a first release only after completing the release gate in the handoff. No hosted service is provisioned by this repository.
