# CodebaseScan security review

Project: Review\-worthy SaaS — fixture export
Audit: 00000000-0000-4000-8000-000000000001
Snapshot: be14a0f1bb2a1bdd297d624383573f6e2b0f9cddee87343b5fdd736509ae2b48
Publication: draft
AI mode: disabled

> Findings are review candidates, not a security certification. No findings does not prove safety.

## Coverage

8 files analyzed. Snapshot stayed within configured limits.

- Project structure profile: completed. Parsed 7 captured TypeScript/JavaScript file\(s\) as data; mapped 2 entry point\(s\), 5 symbol\(s\), 8 call edge\(s\), and 6 security\-relevant fact\(s\).
- Built\-in patterns: completed. Seven bounded regex heuristics executed against inert fixtures. Duration not measured in this reproducible export.
- Application posture: completed. Conservative framework and configuration posture checks executed locally.
- Semgrep: skipped. Not executed for this fixture export.
- Gitleaks: skipped. Not executed for this fixture export.
- Dependency vulnerabilities: skipped. OSV lookup was disabled for this reproducible fixture export.
- Dependency structure: completed. 7 modules and 0 local dependencies were mapped; 0 cycle\(s\) and 4 orphan candidate\(s\) are mechanical review data, not vulnerabilities. Target configuration was not loaded. dependency\-cruiser 18.2.0 is covered by the CodebaseScan scanner compatibility fixtures.
- Code duplication: completed. 0 clone\(s\), 0 duplicated line\(s\), and 0% duplication were measured. Source fragments were discarded. Duplicates are maintainability evidence, not vulnerabilities. jscpd 5.2.0 is covered by the CodebaseScan scanner compatibility fixtures.
- Node.js supply\-chain integrity: completed. Inspected 1 manifest\(s\), 0 lockfile\(s\), 4 dependency specifier\(s\), and 0 resolved lock entry\(s\) without installing packages.
- TypeScript and JavaScript quality metrics: completed. 5 function\(s\) measured; 0 complexity, size, or parameter hotspot\(s\). 0 existing coverage artifact\(s\) imported. Metrics are review evidence, not vulnerabilities.
- Dead code and dependency usage: completed. 0 unused file candidate\(s\), 0 unused dependency candidate\(s\), and 0 unused export candidate\(s\). All target plugins and configuration loaders were disabled. knip 6.35.1 is covered by the CodebaseScan scanner compatibility fixtures.

### Capability summary

- Project structure profile: COMPLETE. Parsed 7 captured TypeScript/JavaScript file\(s\) as data; mapped 2 entry point\(s\), 5 symbol\(s\), 8 call edge\(s\), and 6 security\-relevant fact\(s\).
- Framework\-aware authorization: NOT RUN. No scanner run was recorded for this capability.
- Next.js application security: NOT RUN. No scanner run was recorded for this capability.
- React client security: NOT RUN. No scanner run was recorded for this capability.
- Node.js supply\-chain integrity: COMPLETE. Inspected 1 manifest\(s\), 0 lockfile\(s\), 4 dependency specifier\(s\), and 0 resolved lock entry\(s\) without installing packages.
- JavaScript/TypeScript dependency structure: COMPLETE. 7 modules and 0 local dependencies were mapped; 0 cycle\(s\) and 4 orphan candidate\(s\) are mechanical review data, not vulnerabilities. Target configuration was not loaded. dependency\-cruiser 18.2.0 is covered by the CodebaseScan scanner compatibility fixtures.
- JavaScript/TypeScript code duplication: COMPLETE. 0 clone\(s\), 0 duplicated line\(s\), and 0% duplication were measured. Source fragments were discarded. Duplicates are maintainability evidence, not vulnerabilities. jscpd 5.2.0 is covered by the CodebaseScan scanner compatibility fixtures.
- Code quality metrics: COMPLETE. 5 function\(s\) measured; 0 complexity, size, or parameter hotspot\(s\). 0 existing coverage artifact\(s\) imported. Metrics are review evidence, not vulnerabilities.
- Dead code and dependency usage: COMPLETE. 0 unused file candidate\(s\), 0 unused dependency candidate\(s\), and 0 unused export candidate\(s\). All target plugins and configuration loaders were disabled. knip 6.35.1 is covered by the CodebaseScan scanner compatibility fixtures.
- Built\-in static patterns: COMPLETE. Seven bounded regex heuristics executed against inert fixtures. Duration not measured in this reproducible export.
- Static code analysis: DISABLED. Not executed for this fixture export.
- Secret scanning: DISABLED. Not executed for this fixture export.
- Dependency vulnerabilities: DISABLED. OSV lookup was disabled for this reproducible fixture export.
- Security configuration: COMPLETE. Conservative framework and configuration posture checks executed locally.
- HTTP runtime posture: NOT RUN. No scanner run was recorded for this capability.
- AI contextual analysis: DISABLED. Model inference was disabled. Deterministic findings remain available.
- Infrastructure as Code: NOT SUPPORTED. No dedicated Terraform, CloudFormation, or equivalent policy scanner is implemented.
- Cloud IAM: NOT SUPPORTED. Cloud account and effective IAM policy analysis are outside this release.
- Dynamic exploitation: NOT PERFORMED. CodebaseScan does not exploit targets, brute\-force authentication, or crawl applications.

## Project structure

Status: complete. 7 source files and 226 AST nodes parsed as data.
Frameworks: Next.js App Router, Prisma.
Entry points: 2. Symbols: 5. Call edges: 8. Security facts: 6.

## Mechanical analysis

Dependency structure: 7 modules, 0 local dependencies, 0 cycles, and 4 orphan candidates.

Duplication: 0 clones and 0 duplicated lines (0%).

These measurements are maintainability evidence, not security vulnerabilities.

## Supply-chain integrity

1 manifests, 0 lockfiles, 4 dependency specifiers, and 0 resolved entries were inspected without installing packages.

- dangerousLifecycleScripts: 0
- unsafeDependencySpecs: 0
- weakLockfileIntegrity: 0
- insecureLockfileUrls: 0
- unexpectedLockfileHosts: 0
- manifestLockMismatches: 0

## Code quality

5 functions across 7 files were measured; 0 complexity, size, or parameter hotspots were retained.
Knip candidates: 0 unused files, 0 unused dependencies, 0 unused exports/types.

These are bounded maintenance and test signals, not vulnerabilities or proof of adequate testing.

## Security checklist

Pack: codebasescan\-web\-application 0.4.0. EVIDENCED 0; GAP_CANDIDATE 3; UNVERIFIED 14; PARTIAL 0; FAILED 0; NOT_APPLICABLE 8.

### NOT\_APPLICABLE: Sensitive mutations authenticate a principal

Control: TW\-CTRL\-AUTHN\-001 | Domain: authentication

No supported sensitive mutation boundary was mapped.

Verification: Test each boundary without a session/token and confirm rejection before the sensitive operation.

### UNVERIFIED: Sensitive read routes receive an authentication review

Control: TW\-CTRL\-AUTHN\-002 | Domain: authentication

No missing\-authentication candidate was found across 2 mapped sensitive read route\(s\).

Verification: Test anonymous and wrong\-tenant reads. Confirm intentionally public routes expose only approved fields.

### NOT\_APPLICABLE: Administrative mutations enforce permission

Control: TW\-CTRL\-AUTHZ\-001 | Domain: authorization

No supported admin/internal mutation boundary was mapped.

Verification: Test an authenticated non\-admin principal against every privileged action.

### UNVERIFIED: Dynamic resource access is tenant or owner scoped

Control: TW\-CTRL\-AUTHZ\-002 | Domain: authorization

0 of 1 dynamic database boundary\(s\) contain a recognized tenant, owner, account, organization, or user scope in the captured call arguments.

Verification: Run cross\-tenant and wrong\-owner identifier tests and inspect effective RLS/database policy.

### GAP\_CANDIDATE: Sensitive entry points validate caller\-controlled input

Control: TW\-CTRL\-INPUT\-001 | Domain: input\-validation

0 of 2 sensitive entry point\(s\) contain a recognized validation call within five explicit call hops.

Verification: Test malformed, oversized, unexpected\-type, and boundary input before the sensitive operation.

### GAP\_CANDIDATE: Raw SQL keeps request data out of query structure

Control: TW\-CTRL\-INJECTION\-001 | Domain: input\-validation

1 raw SQL input\-flow candidate\(s\) require review.

Verification: Trace each query fragment, replace structural interpolation with parameters, and test metacharacter payloads without modifying production data.

### NOT\_APPLICABLE: Process execution keeps request data out of commands and executable selection

Control: TW\-CTRL\-COMMAND\-001 | Domain: input\-validation

No supported process execution boundary was mapped.

Verification: Use fixed executables and argument arrays without a shell, then test separators, option injection, encoding, and unexpected executable names.

### NOT\_APPLICABLE: Filesystem paths remain inside server\-owned roots

Control: TW\-CTRL\-PATH\-001 | Domain: input\-validation

No supported filesystem boundary was mapped.

Verification: Test decoded parent traversal, absolute paths, separators, symlinks, and race conditions against the canonical storage root.

### NOT\_APPLICABLE: Outbound destinations are server\-owned or safely constrained

Control: TW\-CTRL\-OUTBOUND\-001 | Domain: integrations

No supported outbound request boundary was mapped.

Verification: Test untrusted public, private, loopback, metadata, DNS\-rebinding, and redirect destinations against the effective egress policy.

### NOT\_APPLICABLE: Redirect destinations are constrained

Control: TW\-CTRL\-REDIRECT\-001 | Domain: integrations

No supported redirect boundary was mapped.

Verification: Test external, scheme\-relative, encoded, mixed\-case, and userinfo\-form destinations against the effective redirect policy.

### UNVERIFIED: File uploads enforce size, content, and storage\-path constraints

Control: TW\-CTRL\-UPLOAD\-001 | Domain: input\-validation

No decisive upload gap was mapped, but the profiler cannot prove that uploads are absent or fully constrained.

Verification: Test byte limits, file count, MIME/content mismatch, polyglots, generated names, traversal, overwrite, and storage execution policy.

### NOT\_APPLICABLE: Webhook authenticity is verified before processing

Control: TW\-CTRL\-WEBHOOK\-001 | Domain: integrations

No supported webhook/callback boundary reaching a sensitive operation was mapped.

Verification: Send missing, invalid, replayed, and stale signatures and confirm rejection before parsing or persistence.

### UNVERIFIED: Browser security policies are declared and observed

Control: TW\-CTRL\-HEADERS\-001 | Domain: browser\-security

No effective runtime response was available to confirm browser policies.

Verification: Observe representative production responses and verify CSP, frame, MIME, referrer, permissions, and transport policies.

### UNVERIFIED: Sensitive cookies use explicit protection attributes

Control: TW\-CTRL\-SESSION\-001 | Domain: authentication

No cookie\-based session signal was mapped.

Verification: Inspect effective Set\-Cookie attributes and test production HTTPS, expiry, logout, fixation, and CSRF behavior.

### UNVERIFIED: Cross\-origin access is intentionally constrained

Control: TW\-CTRL\-CORS\-001 | Domain: browser\-security

No effective cross\-origin policy was observed; same\-origin\-only operation is possible but unverified.

Verification: Test trusted and untrusted Origin values, credential mode, preflight behavior, and server\-side authorization independently.

### GAP\_CANDIDATE: Captured current source has no detected secret exposure candidate

Control: TW\-CTRL\-SECRETS\-001 | Domain: secrets

1 secret or client/server configuration candidate\(s\) require review.

Verification: Review Git history, CI variables, deployment secrets, rotation, and provider\-side secret scanning separately.

### NOT\_APPLICABLE: Resolved dependencies are checked against OSV

Control: TW\-CTRL\-DEPS\-001 | Domain: dependencies

No supported resolved npm/pnpm/Yarn lockfile dependency was available.

Verification: Review advisory freshness, runtime reachability, exploit preconditions, and supported upgrade paths.

### UNVERIFIED: Approved HTTP response posture is observed

Control: TW\-CTRL\-RUNTIME\-001 | Domain: runtime

No target URL was explicitly approved for runtime observation.

Verification: Probe representative production routes and deployment layers under explicit authorization.

### UNVERIFIED: Sensitive operations emit security\-relevant audit events

Control: TW\-CTRL\-LOGGING\-001 | Domain: logging

0 of 2 mapped sensitive boundary\(s\) contain a recognized audit/security logging call.

Verification: Confirm event content, actor, target, outcome, correlation ID, retention, access controls, and alerting in the real logging system.

### UNVERIFIED: Sensitive boundaries define explicit failure handling

Control: TW\-CTRL\-ERRORS\-001 | Domain: logging

0 of 2 mapped sensitive boundary\(s\) contain an explicit catch clause within five call hops.

Verification: Exercise dependency, validation, authorization, and storage failures; confirm safe responses and useful internal diagnostics.

### UNVERIFIED: Next.js caching keeps user and tenant data isolated

Control: TW\-CTRL\-NEXT\-001 | Domain: authorization

No supported user\-specific cache isolation candidate was found in the bounded Next.js scan.

Verification: Test two users or tenants against warm cache entries and inspect Cache\-Control behavior at the deployed edge.

### UNVERIFIED: Next.js client boundaries exclude privileged configuration and response data

Control: TW\-CTRL\-NEXT\-002 | Domain: secrets

No supported privileged public environment or sensitive server response field candidate was found.

Verification: Inspect production client bundles, RSC payloads, and API responses for privileged values.

### UNVERIFIED: Dynamic HTML preserves React output encoding

Control: TW\-CTRL\-REACT\-001 | Domain: input\-validation

No unsanitized dynamic dangerouslySetInnerHTML candidate was found in the bounded React scan.

Verification: Test script, event\-handler, URL, SVG, malformed markup, and mutation\-XSS payloads at every intentional HTML rendering boundary.

### UNVERIFIED: Client navigation, storage, and messaging use constrained browser boundaries

Control: TW\-CTRL\-REACT\-002 | Domain: browser\-security

No supported unsafe client URL, Web Storage, postMessage, or new\-tab pattern was found.

Verification: Exercise untrusted URLs, message origins, storage access after script injection, and external new\-tab navigation.

### UNVERIFIED: Server and Client Component boundaries keep privileged data on the server

Control: TW\-CTRL\-REACT\-003 | Domain: secrets

No supported server\-only import, sensitive prop, async Client Component, or private environment boundary candidate was found.

Verification: Inspect serialized RSC payloads and production client bundles for credentials, privileged session objects, and server\-only modules.

## Findings

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

### MEDIUM: Object lookup needs tenant authorization review

Rule: TW-004 | Source: builtin | Disposition: needs_review

An object lookup begins with an ID filter. This is a review hotspot, not evidence of a missing authorization check; inspect middleware, service policy, RLS and the complete call path.

Remediation: Verify object\-level access for the authenticated tenant. Add a regression test using two tenants and reject cross\-tenant access.

Evidence: src/app/api/projects/\[id\]/route.ts:5-10
Rule TW\-004 matched a review\-relevant code pattern. Runtime exploitability is unverified.

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
- No model, optional external security scanner, or runtime exploit test was executed.
- Bundled dependency and duplication analysis ran against an isolated inert snapshot; its output is maintainability evidence, not a vulnerability verdict.
- All findings are review candidates; there are no automatically confirmed vulnerabilities.
- Regex heuristics can match comments and miss indirect flows. This is not a security certification.
