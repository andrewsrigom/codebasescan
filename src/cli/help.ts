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
  --probe-url <url>         Explicitly run the bounded HTTP posture probe
  --allow-private-network   Allow the explicit probe URL to use a private address
  --secret-history          Inspect bounded Git history with Gitleaks when available
  --allow-partial-snapshot  Accept a project that exceeds snapshot limits
  --format <format>         json, md, html, sarif, sbom, bundle, agent-report, agent-rules
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

Install the bundled CodebaseScan review skill into .codex/skills/codebasescan-review.`,
  open: `Usage: codebasescan open [report-directory|report-root] [--port 4173]

Serve a verified report package or stable report history on 127.0.0.1.`,
  doctor: `Usage: codebasescan doctor

Check the local runtime and optional scanner availability.`,
  finalize: `Usage: codebasescan finalize <after-report> --baseline <before-report> --verification <ledger.json> [options]

Build an immutable before/after report using explicit external verification evidence.`,
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

Export json, md, html, sarif, sbom, bundle, agent-plan, agent-report, agent-rules, or rule-quality.`,
  compare: `Usage: codebasescan compare <base-audit-id> <current-audit-id>

Compare two stored audits without changing scanner evidence.`,
  evaluate: `Usage:
  codebasescan evaluate <audit-id> [more-audit-ids...]
  codebasescan evaluate <report> [more-reports...] --artifacts [--output calibration.json]

Aggregate reviewer-labelled outcomes, evidence quality, location quality, explanation clarity, and manual misses.`,
};

export function renderCliHelp(command?: string): string {
  if (command && commandHelp[command]) return commandHelp[command];
  return `CodebaseScan — local-first codebase auditing

Usage: codebasescan <command> [options]

Start here:
  codebasescan init [project]      Create the safe declarative project config
  codebasescan audit [project]     Audit a project and update one stable report
  codebasescan open [report-root]  View the latest audit and immutable history
  codebasescan doctor              Check this installation
  codebasescan agent install codex Install the optional Codex review skill
  codebasescan --version           Print the installed version

Evidence workflow:
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
