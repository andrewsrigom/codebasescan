# Traceward security review

Project: Review\-worthy SaaS — fixture export
Audit: 00000000-0000-4000-8000-000000000001
Snapshot: be14a0f1bb2a1bdd297d624383573f6e2b0f9cddee87343b5fdd736509ae2b48
Publication: draft
AI mode: disabled

> Findings are review candidates, not a security certification. No findings does not prove safety.

## Coverage

8 files analyzed. Snapshot stayed within configured limits.

- Built\-in patterns: completed. Seven bounded regex heuristics executed against inert fixtures. Duration not measured in this reproducible export.
- Application posture: completed. Conservative framework and configuration posture checks executed locally.
- Semgrep: skipped. Not executed for this fixture export.
- Gitleaks: skipped. Not executed for this fixture export.
- Dependency vulnerabilities: skipped. OSV lookup was disabled for this reproducible fixture export.

### Capability summary

- Built\-in static patterns: COMPLETE. Seven bounded regex heuristics executed against inert fixtures. Duration not measured in this reproducible export.
- Static code analysis: DISABLED. Not executed for this fixture export.
- Secret scanning: DISABLED. Not executed for this fixture export.
- Dependency vulnerabilities: DISABLED. OSV lookup was disabled for this reproducible fixture export.
- Security configuration: COMPLETE. Conservative framework and configuration posture checks executed locally.
- HTTP runtime posture: NOT RUN. No scanner run was recorded for this capability.
- AI contextual analysis: DISABLED. Model inference was disabled. Deterministic findings remain available.
- Infrastructure as Code: NOT SUPPORTED. No dedicated Terraform, CloudFormation, or equivalent policy scanner is implemented.
- Cloud IAM: NOT SUPPORTED. Cloud account and effective IAM policy analysis are outside this release.
- Dynamic exploitation: NOT PERFORMED. Traceward does not exploit targets, brute\-force authentication, or crawl applications.

## Findings

### HIGH: Object lookup needs tenant authorization review

Rule: TW-004 | Source: builtin | Disposition: needs_review

An object lookup begins with an ID filter. Authorization may exist elsewhere; inspect middleware, service policy, RLS and the complete call path.

Remediation: Verify object\-level access for the authenticated tenant. Add a regression test using two tenants and reject cross\-tenant access.

Evidence: src/app/api/projects/\[id\]/route.ts:5-10
Rule TW\-004 matched a review\-relevant code pattern. Runtime exploitability is unverified.

### HIGH: Sensitive configuration uses a public environment name

Rule: TW-005 | Source: builtin | Disposition: needs_review

A sensitive\-looking setting has a browser\-public naming convention. No active credential or actual browser bundle exposure has been verified.

Remediation: Keep privileged credentials in server\-only configuration. If exposure is verified, rotate the credential and review its use.

Evidence: src/lib/config.ts:1-5
Rule TW\-005 matched a review\-relevant code pattern. Runtime exploitability is unverified.

### HIGH: Destructive agent tool needs permission review

Rule: TW-007 | Source: builtin | Disposition: needs_review

A potentially destructive operation appears in an agent tool list. The pattern cannot determine whether approval and authorization are enforced inside the tool.

Remediation: Apply authorization inside each tool, restrict its capability, and require explicit approval where the operation warrants it.

Evidence: src/agents/account.ts:4-8
Rule TW\-007 matched a review\-relevant code pattern. Runtime exploitability is unverified.

### HIGH: Dynamic code execution needs trust\-boundary review

Rule: TW-003 | Source: builtin | Disposition: needs_review

A dynamic execution sink was detected. This is a pattern match, not proof of attacker\-controlled execution.

Remediation: Replace dynamic code execution with explicit operations where possible; otherwise document and enforce the trust boundary.

Evidence: src/lib/expression.ts:1-4
Rule TW\-003 matched a review\-relevant code pattern. Runtime exploitability is unverified.

### HIGH: Raw SQL execution needs input tracing

Rule: TW-001 | Source: builtin | Disposition: needs_review

An unsafe SQL execution API is present. User control of the query and runtime reachability have not been established.

Remediation: Prefer parameterized queries. Trace every value reaching this call before deciding whether an injection vulnerability exists.

Evidence: src/app/api/search/route.ts:3-8
Rule TW\-001 matched a review\-relevant code pattern. Runtime exploitability is unverified.

### MEDIUM: HTML rendering bypass needs sanitization review

Rule: TW-002 | Source: builtin | Disposition: needs_review

Raw HTML reaches a React rendering sink. The scanner does not prove that the value is attacker\-controlled or unsanitized.

Remediation: Establish the source of the HTML and verify an appropriate sanitizer. Prefer rendering text when rich HTML is unnecessary.

Evidence: src/components/preview.tsx:1-4
Rule TW\-002 matched a review\-relevant code pattern. Runtime exploitability is unverified.

### MEDIUM: Wildcard cross\-origin policy needs context review

Rule: TW-006 | Source: builtin | Disposition: needs_review

A wildcard CORS origin was found. Public endpoints may intentionally permit it; authentication and exposed data determine the risk.

Remediation: Define expected browser origins and validate the credential model. Do not treat CORS as an authorization mechanism.

Evidence: src/lib/cors.ts:1-4
Rule TW\-006 matched a review\-relevant code pattern. Runtime exploitability is unverified.

## Limitations

- This is an inert fixture export generated directly by the deterministic core, not an executed LangGraph audit.
- No model, external scanner, or runtime exploit test was executed.
- All findings are review candidates; there are no automatically confirmed vulnerabilities.
- Regex heuristics can match comments and miss indirect flows. This is not a security certification.
