const auditModes =
  'security,saas,accessibility-static,privacy,reliability,next-react,maintainability,release-readiness,web-posture';

const commandHelp: Record<string, string> = {
  audit: `Usage: codebasescan audit [project] [options]

Run a complete, non-interactive audit. Target project code is read as data and is never executed.

Options:
  --report-dir <path>       Stable report root (default: codebasescan-report)
  --modes <list>            Comma-separated modes: ${auditModes}
  --policy <profile>        advisory, balanced, or strict
  --fail-on <severity>      Compatibility gate: critical, high, medium, low, or info
  --baseline <report.json>  Compare only new findings against a previous audit
  --reviews <ledger.json>   Apply portable human review decisions
  --suppressions <file>     Apply portable suppressions
  --probe-url <url>         Explicit bounded HTTP posture probe (repeat up to 3 times)
  --allow-private-network   Allow the explicit probe URL to use a private address
  --secret-history          Inspect bounded Git history with Gitleaks when available
  --allow-partial-snapshot  Accept a project that exceeds snapshot limits
  --format <format>         json, md, html, sarif, sbom, bundle, agent-context, agent-report, agent-rules
  --output <file>           Write a single-format artifact instead of the static report
  --open                    Serve the report on loopback after the audit
  --port <number>           Loopback report server port (default: 4173)
  --non-interactive         Fail instead of opening an interactive report server
  --quiet                   Hide progress messages
  --verbose                 Show every scanner duration`,
  init: `Usage: codebasescan init [project] [--force]

Create codebasescan.config.json with a bundled JSON Schema for editor autocomplete.
Existing files are preserved unless --force is explicit.`,
  agent: `Usage: codebasescan agent install codex [project] [--force]

Install the bundled review, gap-review, and fix-verification skills into .agents/skills.`,
  open: `Usage: codebasescan open [report-directory] [--port 4173]

Serve a verified report package on 127.0.0.1.`,
  doctor: `Usage: codebasescan doctor

Check the local runtime and optional scanner availability.`,
  report: `Usage: codebasescan report verify [report-root] [--json]

Verify the report manifest, every artifact hash, and audit identity before reading evidence.`,
  findings: `Usage: codebasescan findings list [report-root] [options]

List verified finding candidates. Default output is limited to 20 rows.

Options:
  --severity <value>  Exact severity: critical, high, medium, low, or info
  --rule <rule-id>    Exact rule ID
  --path <file>       Exact relative source path
  --limit <1..100>   Maximum rows (default: 20)
  --json             Compact machine-readable rows`,
  finding: `Usage: codebasescan finding show <report-root> <finding-id> [--json]

Read one verified finding with its captured evidence.`,
  coverage: `Usage: codebasescan coverage show [report-root] [--json]

Show complete and incomplete capabilities without treating skipped work as safe.`,
  finalize: `Usage: codebasescan finalize <after-report> --baseline <before-report> --verification <ledger.json> [options]

Build a before/after report using explicit external verification evidence.`,
  task: `Usage: codebasescan task <report> <task-id> [--output task.json]

Export one bounded remediation task for an agent or another tool.`,
  review: `Usage: codebasescan review <report> <finding-id> <decision> --note <evidence> [--output ledger.json]

Record confirmed, false_positive, or accepted_risk as portable human review evidence.`,
  suppress: `Usage: codebasescan suppress <report> <finding-id> --owner <name> --justification <reason> --evidence <record> [options]

Create or update a portable, expiring suppression ledger.`,
  calibration: `Usage:
  codebasescan calibration review <report> <finding-id> <outcome> --reviewer <name> --note <evidence> --evidence <rating> --location <rating> --explanation <rating>
  codebasescan calibration miss <report> --file <relative-path> --reviewer <name> --note <evidence> [--line <number>] [--expected-rule <id>]
  codebasescan calibration scope <report> --candidates <partial|complete> --false-negatives <not_performed|sampled|complete> --reviewer <name> --note <scope>

Record independent real-project ground truth without changing scanner findings.
Outcomes: true_positive, false_positive, not_applicable, inconclusive.
Evidence/location ratings: correct, incorrect, uncertain.
Explanation ratings: clear, unclear, uncertain.`,
  advisories: `Usage: codebasescan advisories update <project>

Explicitly refresh the local OSV advisory snapshot for resolved dependencies.`,
  register: `Usage: codebasescan register <project>

Register a validated project root in the local persistent workspace.`,
  scan: `Usage: codebasescan scan <project> [audit options]

Queue an audit for the separately running local worker.`,
  list: `Usage: codebasescan list

List audits stored in the local persistent workspace.`,
  export: `Usage: codebasescan export <audit-id> <format>

Export json, md, html, sarif, sbom, bundle, agent-plan, agent-context, agent-report, agent-rules, or rule-quality.`,
  compare: `Usage: codebasescan compare <base-audit-id> <current-audit-id>

Compare two stored audits without changing scanner evidence.`,
  evaluate: `Usage:
  codebasescan evaluate <audit-id> [more-audit-ids...]
  codebasescan evaluate <report> [more-reports...] --artifacts [--output calibration.json]
  codebasescan evaluate <report> [more-reports...] --artifacts --gate v1 [--output gate.json]

Aggregate reviewer-labelled outcomes, evidence quality, location quality, explanation clarity, and manual misses.
The v1 gate checks the measurable real-project calibration subset and exits non-zero until it passes.`,
};

export function renderCliHelp(command?: string): string {
  if (command && commandHelp[command]) return commandHelp[command];
  return `CodebaseScan — local-first codebase auditing

Usage: codebasescan <command> [options]

Start here:
  codebasescan init [project]      Create the safe declarative project config
  codebasescan audit [project]     Audit a project and update one stable report
  codebasescan open [report-root]  View the current audit
  codebasescan doctor              Check this installation
  codebasescan report verify       Verify a portable report package
  codebasescan findings list       List candidates by stable ID
  codebasescan finding show        Read one candidate and its evidence
  codebasescan coverage show       Inspect incomplete capabilities
  codebasescan agent install codex Install the optional Codex review skill
  codebasescan --version           Print the installed version

Evidence workflow:
  report, findings, finding, coverage  Read verified evidence
  agent      Install agent integrations
  finalize   Build a verified before/after report
  task       Export one remediation task for an agent
  review     Record a portable human decision
  suppress   Record an evidence-backed suppression
  calibration Record independent detector-quality ground truth

Persistent local workflow:
  register, scan, list, export, compare, evaluate, advisories update

Run codebasescan <command> --help for command details. No target project code is executed.`;
}
