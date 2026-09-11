import { z } from 'zod';
import type { Finding } from './types.ts';

export const agentReviewRulePackVersion = 1 as const;

const findingCategories = [
  'authentication',
  'authorization',
  'injection',
  'secrets',
  'configuration',
  'ai-security',
  'dependencies',
  'accessibility',
  'privacy',
  'reliability',
  'code',
] as const satisfies readonly Finding['category'][];

const findingSources = [
  'builtin',
  'posture',
  'ast',
  'saas',
  'next',
  'react',
  'accessibility',
  'axe',
  'web',
  'privacy',
  'reliability',
  'environment',
  'supply-chain',
  'http-probe',
  'osv',
  'semgrep',
  'gitleaks',
] as const satisfies readonly Finding['source'][];

const boundedText = (maximum: number) => z.string().min(1).max(maximum);
const boundedList = (maximumItems: number, maximumText: number) =>
  z.array(boundedText(maximumText)).min(1).max(maximumItems);

export const agentReviewRuleSchema = z
  .object({
    id: z.string().regex(/^CBS-AI-[A-Z0-9-]+$/),
    version: z.literal(agentReviewRulePackVersion),
    title: boundedText(160),
    domain: z.enum([
      'identity',
      'data-access',
      'input-flow',
      'secret-and-ai-boundaries',
      'configuration',
      'supply-chain',
      'accessibility',
      'privacy',
      'reliability',
      'maintainability',
    ]),
    appliesTo: z
      .object({
        categories: z.array(z.enum(findingCategories)).min(1),
        sources: z.array(z.enum(findingSources)).optional(),
      })
      .strict(),
    objective: boundedText(500),
    questions: boundedList(8, 300),
    evidenceRequired: boundedList(8, 300),
    safeSignals: boundedList(8, 300),
    riskSignals: boundedList(8, 300),
    falsePositiveChecks: boundedList(8, 300),
    searchHints: boundedList(10, 100),
    limitations: boundedList(6, 300),
  })
  .strict();

export type AgentReviewRule = z.infer<typeof agentReviewRuleSchema>;

export const agentReviewRulePackSchema = z
  .object({
    schemaVersion: z.literal(agentReviewRulePackVersion),
    kind: z.literal('codebasescan-agent-review-rule-pack'),
    name: z.literal('CodebaseScan web application review'),
    rules: z.array(agentReviewRuleSchema).min(1).max(100),
  })
  .strict();

export type AgentReviewRulePack = z.infer<typeof agentReviewRulePackSchema>;

const rules: AgentReviewRule[] = [
  {
    id: 'CBS-AI-IDENTITY',
    version: 1,
    title: 'Authentication and session boundaries',
    domain: 'identity',
    appliesTo: { categories: ['authentication'] },
    objective:
      'Determine whether a protected operation has an effective server-side identity and session boundary.',
    questions: [
      'Where is the authenticated principal established?',
      'Can the operation run when identity or session state is missing, stale, or forged?',
      'Are authentication checks applied on the server before sensitive effects?',
    ],
    evidenceRequired: [
      'The entry point and sensitive operation connected by captured call evidence.',
      'The server-side authentication or session validation control on that path.',
    ],
    safeSignals: [
      'A server-owned principal is required before the sensitive operation.',
      'Session validity is checked at the request boundary or a resolved wrapper.',
    ],
    riskSignals: [
      'Caller-controlled identity is trusted directly.',
      'A sensitive operation is reachable without a mapped authentication decision.',
    ],
    falsePositiveChecks: [
      'Look for authentication in resolved middleware, wrappers, or parent route handlers.',
      'Keep infrastructure-only or provider-side enforcement unverified when it is not captured.',
    ],
    searchHints: ['auth', 'session', 'principal', 'userId', 'getServerSession', 'middleware'],
    limitations: [
      'Static source cannot prove the runtime identity-provider or session configuration.',
    ],
  },
  {
    id: 'CBS-AI-AUTHORIZATION',
    version: 1,
    title: 'Authorization and tenant isolation',
    domain: 'data-access',
    appliesTo: { categories: ['authorization'] },
    objective:
      'Trace resource access from the caller-controlled identifier to the data operation and identify the effective ownership, role, or tenant constraint.',
    questions: [
      'Which caller controls the resource or tenant identifier?',
      'Where is ownership, role, permission, or tenant scope enforced?',
      'Does the scoped decision dominate every sensitive read or mutation on the path?',
    ],
    evidenceRequired: [
      'The request boundary, identifier source, authorization decision, and final data operation.',
      'Resolved wrapper or middleware evidence when authorization is not local to the entry point.',
    ],
    safeSignals: [
      'The data query is constrained by a server-owned tenant or owner value.',
      'A role or permission decision occurs before the privileged effect.',
    ],
    riskSignals: [
      'A request-supplied tenant, owner, role, or resource identifier reaches a query unchanged.',
      'Authorization is enforced only in client code.',
    ],
    falsePositiveChecks: [
      'Search resolved callers, middleware, database helpers, and policy wrappers.',
      'Do not infer row-level security or gateway policy when it is outside the snapshot.',
    ],
    searchHints: [
      'tenant',
      'workspace',
      'organization',
      'ownerId',
      'authorize',
      'permission',
      'role',
    ],
    limitations: ['Database RLS and external authorization policy require separate evidence.'],
  },
  {
    id: 'CBS-AI-INPUT-FLOW',
    version: 1,
    title: 'Untrusted input and privileged sinks',
    domain: 'input-flow',
    appliesTo: { categories: ['injection'] },
    objective:
      'Establish whether caller-controlled input reaches an interpreter, query, path, redirect, request, or object-write sink without an effective constraint.',
    questions: [
      'What is the original trust boundary for the value?',
      'Which transformations and validations occur before the sink?',
      'Does the control constrain the exact syntax or destination consumed by the sink?',
    ],
    evidenceRequired: [
      'The input source, resolved data or call path, validation control, and final sink.',
      'The accepted-value constraint or parameterization mechanism.',
    ],
    safeSignals: [
      'Parameterized APIs or strict allowlists prevent caller-controlled syntax.',
      'Validated values remain constrained through the final operation.',
    ],
    riskSignals: [
      'Concatenation, interpolation, dynamic evaluation, or unconstrained destinations.',
      'Validation applies to a different value or occurs after the sensitive effect.',
    ],
    falsePositiveChecks: [
      'Trace aliases and wrappers before assuming the value is unvalidated.',
      'Distinguish constant template composition from caller-controlled interpolation.',
    ],
    searchHints: ['validate', 'parse', 'safeParse', 'query', 'exec', 'eval', 'fetch', 'redirect'],
    limitations: ['Bounded static call and data flow may miss dynamic dispatch or runtime guards.'],
  },
  {
    id: 'CBS-AI-SECRET-BOUNDARIES',
    version: 1,
    title: 'Secrets and AI tool boundaries',
    domain: 'secret-and-ai-boundaries',
    appliesTo: { categories: ['secrets', 'ai-security'] },
    objective:
      'Review whether sensitive values or untrusted model content cross a client, prompt, log, URL, or privileged-tool boundary.',
    questions: [
      'Is the value a real secret, sensitive-shaped fixture, or public configuration?',
      'Can untrusted content influence instructions, tool arguments, or privileged effects?',
      'What redaction, allowlist, confirmation, or isolation control exists?',
    ],
    evidenceRequired: [
      'The value origin, destination boundary, and directly visible protection.',
      'Tool or model permissions when an AI-controlled action is involved.',
    ],
    safeSignals: [
      'Secrets remain server-side and are redacted before logs, prompts, URLs, or client bundles.',
      'Model outputs are schema-validated and privileged tool calls are allowlisted.',
    ],
    riskSignals: [
      'Credential-shaped values enter source, client code, logs, URLs, or prompts.',
      'Repository or user content is treated as trusted agent instruction.',
    ],
    falsePositiveChecks: [
      'Differentiate test placeholders and documented examples from active credentials.',
      'Do not send secret matches to a model while investigating them.',
    ],
    searchHints: ['secret', 'token', 'apiKey', 'password', 'prompt', 'tool', 'invoke', 'bindTools'],
    limitations: [
      'Secret rotation, provider permissions, and deployed tool policy are external evidence.',
    ],
  },
  {
    id: 'CBS-AI-CONFIGURATION',
    version: 1,
    title: 'Security configuration and runtime posture',
    domain: 'configuration',
    appliesTo: { categories: ['configuration'] },
    objective:
      'Connect captured declarations to the application behavior they are expected to protect without treating source configuration as runtime proof.',
    questions: [
      'Which application boundary consumes this declaration?',
      'Can another layer override, omit, or weaken it?',
      'What runtime observation would verify the effective behavior?',
    ],
    evidenceRequired: [
      'The captured declaration and the framework or runtime boundary that consumes it.',
      'Explicit missing, partial, or observed runtime evidence.',
    ],
    safeSignals: [
      'A bounded declaration covers the intended route, response, cookie, origin, or environment boundary.',
      'Authorized runtime evidence agrees with the source declaration.',
    ],
    riskSignals: [
      'A protection is absent, wildcarded, client-controlled, or applied to only part of the app.',
      'Source and observed runtime posture disagree.',
    ],
    falsePositiveChecks: [
      'Search framework wrappers and every captured application root.',
      'Keep proxy, hosting, and deployment behavior unknown when not observed.',
    ],
    searchHints: [
      'headers',
      'cookies',
      'cors',
      'origin',
      'env',
      'Content-Security-Policy',
      'config',
    ],
    limitations: [
      'Source declarations do not establish the deployed response or infrastructure policy.',
    ],
  },
  {
    id: 'CBS-AI-SUPPLY-CHAIN',
    version: 1,
    title: 'Dependencies and supply-chain integrity',
    domain: 'supply-chain',
    appliesTo: { categories: ['dependencies'] },
    objective:
      'Determine the dependency relationship, source reference, affected version path, and safest supported remediation without overstating reachability.',
    questions: [
      'Is the package direct, transitive, development-only, or a local workspace package?',
      'What lockfile path and source-reference evidence exists?',
      'Does the advisory provide a compatible fixed version for every affected path?',
    ],
    evidenceRequired: [
      'Manifest, lockfile relationship, advisory identity, and available parent paths.',
      'Source-reference or feature evidence when discussing possible runtime reachability.',
    ],
    safeSignals: [
      'Resolved integrity metadata and an intentional registry or local workspace source.',
      'All affected paths have a supported fixed-version plan.',
    ],
    riskSignals: [
      'Unpinned remote sources, missing integrity, manifest drift, or affected resolved versions.',
      'Lifecycle scripts or unexpected registries requiring trust review.',
    ],
    falsePositiveChecks: [
      'Do not equate package presence with execution of the vulnerable feature.',
      'Check workspace and private-registry intent before recommending a source change.',
    ],
    searchHints: ['package.json', 'lockfile', 'import', 'require', 'dependency', 'workspace'],
    limitations: ['Static dependency presence does not prove vulnerable code execution.'],
  },
  {
    id: 'CBS-AI-ACCESSIBILITY',
    version: 1,
    title: 'Accessible interaction and semantics',
    domain: 'accessibility',
    appliesTo: { categories: ['accessibility'] },
    objective:
      'Determine whether captured JSX semantics create a likely keyboard, naming, focus, or assistive-technology barrier and identify the runtime check still required.',
    questions: [
      'Which rendered control or interaction is represented by the source?',
      'Is an accessible name, native semantic, keyboard behavior, or focus behavior provided elsewhere?',
      'Which browser state must be exercised to verify the candidate?',
    ],
    evidenceRequired: [
      'The component markup, relevant wrapper, and any imported Axe evidence.',
      'The interaction or rendered state required for verification.',
    ],
    safeSignals: [
      'Native semantic controls and explicit accessible names are preserved.',
      'Imported authorized runtime evidence covers the affected rendered state.',
    ],
    riskSignals: [
      'Click-only non-interactive elements, unlabeled controls, or broken semantic relationships.',
      'Dynamic focus behavior has no visible management path.',
    ],
    falsePositiveChecks: [
      'Inspect component wrappers and prop spreading before assuming semantics are absent.',
      'Keep contrast, layout, and assistive-technology behavior unverified without runtime evidence.',
    ],
    searchHints: ['aria-', 'role', 'tabIndex', 'onClick', 'label', 'focus', 'dialog'],
    limitations: [
      'Static JSX cannot prove rendered accessibility or assistive-technology behavior.',
    ],
  },
  {
    id: 'CBS-AI-PRIVACY',
    version: 1,
    title: 'Sensitive-data exposure and transfer',
    domain: 'privacy',
    appliesTo: { categories: ['privacy'] },
    objective:
      'Trace sensitive-shaped data into URLs, logs, browser storage, client components, analytics, or external requests and identify the purpose and protection evidence.',
    questions: [
      'What data class and subject does the value represent?',
      'Where is it stored, logged, rendered, or transferred?',
      'Is minimization, redaction, retention, consent, or access control visible?',
    ],
    evidenceRequired: [
      'The sensitive-shaped source, transfer or storage destination, and visible protection.',
      'Declared purpose or retention evidence when available.',
    ],
    safeSignals: [
      'Sensitive values are minimized or redacted before observable client and network boundaries.',
      'Storage and transfer are scoped to a documented purpose and access boundary.',
    ],
    riskSignals: [
      'Sensitive values enter query strings, logs, analytics, or persistent browser storage.',
      'Server-owned data crosses into a client component without demonstrated need.',
    ],
    falsePositiveChecks: [
      'Confirm that the value is actually sensitive rather than only similarly named.',
      'Trace sanitization and serialization helpers before concluding the raw value crosses the boundary.',
    ],
    searchHints: ['email', 'phone', 'token', 'query', 'logger', 'analytics', 'localStorage'],
    limitations: [
      'Purpose, consent, retention, and actual runtime transfers require external evidence.',
    ],
  },
  {
    id: 'CBS-AI-RELIABILITY',
    version: 1,
    title: 'Failure handling and repeatable effects',
    domain: 'reliability',
    appliesTo: { categories: ['reliability'] },
    objective:
      'Review timeouts, retries, idempotency, error propagation, cleanup, and duplicate delivery around important application effects.',
    questions: [
      'What failure or duplicate-delivery condition can reach this path?',
      'Is the operation safe to retry, bounded by a timeout, and observable when it fails?',
      'Can cleanup or acknowledgement occur before the protected effect is durable?',
    ],
    evidenceRequired: [
      'The request, job, webhook, or external-call boundary and its failure path.',
      'Timeout, retry, idempotency, cleanup, and logging controls that are directly visible.',
    ],
    safeSignals: [
      'Bounded timeouts and retry policies preserve a visible terminal failure.',
      'Idempotency or durable event claims precede repeatable side effects.',
    ],
    riskSignals: [
      'Caught failures are discarded or requests can wait without a bound.',
      'Duplicate deliveries can repeat billing, messaging, or state mutations.',
    ],
    falsePositiveChecks: [
      'Search wrapper clients, queue configuration, and caller-level error handling.',
      'Do not infer platform retries or timeouts without captured evidence.',
    ],
    searchHints: ['timeout', 'retry', 'catch', 'idempot', 'webhook', 'queue', 'AbortSignal'],
    limitations: [
      'Runtime queues, provider retry behavior, and operational recovery remain unverified.',
    ],
  },
  {
    id: 'CBS-AI-MAINTAINABILITY',
    version: 1,
    title: 'Maintainability and change risk',
    domain: 'maintainability',
    appliesTo: { categories: ['code'] },
    objective:
      'Use mechanical complexity, duplication, coupling, cycle, dead-code, and test-reference evidence to identify concentrated change risk without calling it a vulnerability.',
    questions: [
      'Is the candidate reachable through framework conventions, dynamic imports, generation, or runtime registration?',
      'Which dependencies and tests increase or reduce the change risk?',
      'Can the concern be reduced without broad unrelated refactoring?',
    ],
    evidenceRequired: [
      'The mechanical measurement, affected symbols or modules, dependency edges, and related test evidence.',
      'Framework reachability or generated-code context when dead code is suspected.',
    ],
    safeSignals: [
      'The code has a documented dynamic or framework entry path.',
      'Focused tests and cohesive boundaries limit the blast radius.',
    ],
    riskSignals: [
      'Complexity, duplication, cycles, or coupling concentrate unrelated responsibilities.',
      'Apparently unused code has no captured entry, import, script, or framework convention.',
    ],
    falsePositiveChecks: [
      'Check generated routes, runtime registration, scripts, and framework conventions.',
      'Keep mechanical observations separate from security findings.',
    ],
    searchHints: ['dynamic import', 'register', 'route', 'script', 'test', 'generated'],
    limitations: ['Mechanical structure does not establish runtime reachability or defect impact.'],
  },
];

export const agentReviewRulePack: AgentReviewRulePack = agentReviewRulePackSchema.parse({
  schemaVersion: agentReviewRulePackVersion,
  kind: 'codebasescan-agent-review-rule-pack',
  name: 'CodebaseScan web application review',
  rules,
});

export function reviewRulesForFinding(finding: Finding): AgentReviewRule[] {
  return agentReviewRulePack.rules.filter(
    (rule) =>
      rule.appliesTo.categories.includes(finding.category) &&
      (!rule.appliesTo.sources || rule.appliesTo.sources.includes(finding.source)),
  );
}

export function parseAgentReviewRulePack(value: unknown): AgentReviewRulePack {
  return agentReviewRulePackSchema.parse(value);
}
