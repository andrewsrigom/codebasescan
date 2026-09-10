import type {
  AuditReport,
  Finding,
  ProjectEntrypoint,
  ProjectFact,
  ScannerRun,
  SecurityChecklist,
  SecurityControlEvidenceRef,
  SecurityControlResult,
  SecurityControlStatus,
} from './types.ts';
import {
  isAdministrativeEntrypoint,
  isMutatingEntrypoint,
  isWebhookEntrypoint,
  effectiveEntrypointFacts,
  sensitiveFacts,
} from './project-graph.ts';

type ChecklistInput = Pick<
  AuditReport,
  'projectProfile' | 'findings' | 'scanners' | 'httpProbe' | 'dependencies'
>;

interface EntrypointContext {
  entrypoint: ProjectEntrypoint;
  facts: ProjectFact[];
}

function references(
  kind: SecurityControlEvidenceRef['kind'],
  ids: (string | undefined)[],
): SecurityControlEvidenceRef[] {
  return [...new Set(ids.filter((id): id is string => Boolean(id)))]
    .slice(0, 100)
    .map((id) => ({ kind, id }));
}

function findingsByRule(findings: Finding[], rules: string[]): Finding[] {
  return findings.filter((finding) => rules.includes(finding.ruleId));
}

function scanner(scanners: ScannerRun[], id: string): ScannerRun | undefined {
  return scanners.find((item) => item.id === id);
}

function control(
  input: Omit<SecurityControlResult, 'limitations'> & { limitations?: string[] },
): SecurityControlResult {
  return { ...input, limitations: input.limitations ?? [] };
}

function gapStatus(
  gaps: Finding[],
  coverage: ScannerRun | undefined,
  profilePartial: boolean,
  evidenced: boolean,
  partiallyEvidenced = false,
): SecurityControlStatus {
  if (gaps.length) return 'GAP_CANDIDATE';
  if (coverage?.status === 'failed') return 'FAILED';
  if (coverage?.status === 'skipped' || !coverage) return 'UNVERIFIED';
  if (profilePartial || coverage.status === 'partial' || partiallyEvidenced) return 'PARTIAL';
  return evidenced ? 'EVIDENCED' : 'UNVERIFIED';
}

function contextEvidence(
  contexts: EntrypointContext[],
  kinds: ProjectFact['kind'][],
): SecurityControlEvidenceRef[] {
  return references(
    'profile-fact',
    contexts.flatMap((context) =>
      context.facts.filter((fact) => kinds.includes(fact.kind)).map((fact) => fact.id),
    ),
  );
}

export function buildSecurityChecklist(input: ChecklistInput): SecurityChecklist {
  const { projectProfile: profile, findings, scanners, httpProbe, dependencies } = input;
  const astRun = scanner(scanners, 'ast-security');
  const saasRun = scanner(scanners, 'saas-security');
  const nextRun = scanner(scanners, 'next-security');
  const reactRun = scanner(scanners, 'react-security');
  const postureRun = scanner(scanners, 'posture');
  const gitleaksRun = scanner(scanners, 'gitleaks');
  const historySecretsScanned = gitleaksRun?.detail.includes('approved Git history') ?? false;
  const osvRun = scanner(scanners, 'osv');
  const httpRun = scanner(scanners, 'http-probe');
  const profilePartial = profile?.status === 'partial';
  const noMappedApplicability: SecurityControlStatus =
    !profile || profile.status === 'unsupported'
      ? 'UNVERIFIED'
      : profile.status === 'partial'
        ? 'PARTIAL'
        : 'NOT_APPLICABLE';
  const contexts: EntrypointContext[] = (profile?.entrypoints ?? [])
    .filter((entrypoint) => entrypoint.kind !== 'middleware')
    .map((entrypoint) => ({ entrypoint, facts: effectiveEntrypointFacts(profile!, entrypoint) }));
  const sensitiveContexts = contexts.filter((context) => sensitiveFacts(context.facts).length);
  const mutations = sensitiveContexts.filter(
    (context) =>
      isMutatingEntrypoint(context.entrypoint) && !isWebhookEntrypoint(context.entrypoint),
  );
  const reads = sensitiveContexts.filter((context) =>
    context.entrypoint.methods.some((method) => ['GET', 'HEAD'].includes(method)),
  );
  const administrative = mutations.filter((context) =>
    isAdministrativeEntrypoint(context.entrypoint),
  );
  const resourceContexts = sensitiveContexts.filter(
    (context) =>
      context.entrypoint.dynamicParameters.length &&
      context.facts.some((fact) => fact.kind === 'database'),
  );
  const webhooks = sensitiveContexts.filter((context) => isWebhookEntrypoint(context.entrypoint));
  const astRefs = references('scanner', [astRun?.id]);
  const saasRefs = references('scanner', [saasRun?.id]);
  const controls: SecurityControlResult[] = [];

  const authGaps = findingsByRule(findings, ['TW-AST001']);
  const authenticated = mutations.filter((context) =>
    context.facts.some((fact) => ['authentication', 'authorization'].includes(fact.kind)),
  );
  controls.push(
    control({
      id: 'TW-CTRL-AUTHN-001',
      domain: 'authentication',
      title: 'Sensitive mutations authenticate a principal',
      status: mutations.length
        ? gapStatus(
            authGaps,
            astRun,
            profilePartial,
            authenticated.length === mutations.length,
            authenticated.length > 0 && authenticated.length < mutations.length,
          )
        : noMappedApplicability,
      rationale: mutations.length
        ? `${authenticated.length} of ${mutations.length} mapped sensitive mutation boundary(s) contain a recognized authentication or authorization fact in applicable middleware or within five explicit call hops.`
        : 'No supported sensitive mutation boundary was mapped.',
      applicability:
        'Applies to mapped mutating routes and server actions that reach database, raw SQL, command, or file operations. Webhooks are evaluated separately.',
      evidence: [
        ...references(
          'finding',
          authGaps.map((item) => item.id),
        ),
        ...contextEvidence(authenticated, ['authentication', 'authorization']),
        ...astRefs,
      ],
      verification:
        'Test each boundary without a session/token and confirm rejection before the sensitive operation.',
      limitations: [
        'Gateway, middleware, identity-provider, and database policy outside the bounded map may change the result.',
      ],
    }),
  );

  const readAuthGaps = findingsByRule(findings, ['TW-NEXT001']);
  controls.push(
    control({
      id: 'TW-CTRL-AUTHN-002',
      domain: 'authentication',
      title: 'Sensitive read routes receive an authentication review',
      status: reads.length
        ? gapStatus(readAuthGaps, nextRun, profilePartial, nextRun?.status === 'completed')
        : noMappedApplicability,
      rationale: readAuthGaps.length
        ? `${readAuthGaps.length} sensitive Next.js read route(s) have no mapped authentication guard.`
        : reads.length
          ? `No missing-authentication candidate was found across ${reads.length} mapped sensitive read route(s).`
          : 'No supported sensitive read route was mapped.',
      applicability:
        'Applies to mapped Next.js GET and HEAD routes that reach database, raw SQL, command, or file operations.',
      evidence: [
        ...references(
          'finding',
          readAuthGaps.map((item) => item.id),
        ),
        ...references('scanner', [nextRun?.id]),
      ],
      verification:
        'Test anonymous and wrong-tenant reads. Confirm intentionally public routes expose only approved fields.',
      limitations: [
        'Gateway controls and public-route intent outside the captured source remain unverified.',
      ],
    }),
  );

  const adminGaps = findingsByRule(findings, ['TW-AST002']);
  const authorizedAdmin = administrative.filter((context) =>
    context.facts.some((fact) => fact.kind === 'authorization'),
  );
  controls.push(
    control({
      id: 'TW-CTRL-AUTHZ-001',
      domain: 'authorization',
      title: 'Administrative mutations enforce permission',
      status: administrative.length
        ? gapStatus(
            adminGaps,
            astRun,
            profilePartial,
            authorizedAdmin.length === administrative.length,
            authorizedAdmin.length > 0 && authorizedAdmin.length < administrative.length,
          )
        : noMappedApplicability,
      rationale: administrative.length
        ? `${authorizedAdmin.length} of ${administrative.length} privileged-looking mutation boundary(s) contain a recognized permission decision.`
        : 'No supported admin/internal mutation boundary was mapped.',
      applicability:
        'Applies to mapped admin/internal routes and actions that reach sensitive operations.',
      evidence: [
        ...references(
          'finding',
          adminGaps.map((item) => item.id),
        ),
        ...contextEvidence(authorizedAdmin, ['authorization']),
        ...astRefs,
      ],
      verification: 'Test an authenticated non-admin principal against every privileged action.',
    }),
  );

  const scopeGaps = findingsByRule(findings, ['TW-AST003', 'TW-NEXT002']);
  const scopedResources = resourceContexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'resource-scope'),
  );
  controls.push(
    control({
      id: 'TW-CTRL-AUTHZ-002',
      domain: 'authorization',
      title: 'Dynamic resource access is tenant or owner scoped',
      status: resourceContexts.length
        ? gapStatus(
            scopeGaps,
            astRun,
            profilePartial,
            scopedResources.length === resourceContexts.length,
            scopedResources.length > 0 && scopedResources.length < resourceContexts.length,
          )
        : noMappedApplicability,
      rationale: resourceContexts.length
        ? `${scopedResources.length} of ${resourceContexts.length} dynamic database boundary(s) contain a recognized tenant, owner, account, organization, or user scope in the captured call arguments.`
        : 'No supported dynamic resource access was mapped.',
      applicability:
        'Applies when a caller-selectable path parameter reaches a mapped database operation.',
      evidence: [
        ...references(
          'finding',
          scopeGaps.map((item) => item.id),
        ),
        ...contextEvidence(scopedResources, ['resource-scope']),
        ...references('scanner', [astRun?.id, nextRun?.id]),
      ],
      verification:
        'Run cross-tenant and wrong-owner identifier tests and inspect effective RLS/database policy.',
      limitations: [
        'Scope passed through an unrecognized object or enforced by RLS may remain unverified.',
      ],
    }),
  );

  const validated = sensitiveContexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'validation'),
  );
  const validationGaps = findingsByRule(findings, [
    'TW-NEXT006',
    'TW-AST013',
    'TW-AST014',
    'TW-AST016',
    'TW-AST017',
    'TW-AST018',
  ]);
  controls.push(
    control({
      id: 'TW-CTRL-INPUT-001',
      domain: 'input-validation',
      title: 'Sensitive entry points validate caller-controlled input',
      status: sensitiveContexts.length
        ? validationGaps.length
          ? 'GAP_CANDIDATE'
          : profilePartial
            ? 'PARTIAL'
            : validated.length === sensitiveContexts.length
              ? 'EVIDENCED'
              : 'GAP_CANDIDATE'
        : noMappedApplicability,
      rationale: sensitiveContexts.length
        ? `${validated.length} of ${sensitiveContexts.length} sensitive entry point(s) contain a recognized validation call within five explicit call hops.`
        : 'No supported sensitive entry point was mapped.',
      applicability: 'Applies to mapped routes/actions that reach sensitive operations.',
      evidence: [
        ...references(
          'finding',
          validationGaps.map((item) => item.id),
        ),
        ...contextEvidence(validated, ['validation']),
        ...references('scanner', [nextRun?.id]),
      ],
      verification:
        'Test malformed, oversized, unexpected-type, and boundary input before the sensitive operation.',
      limitations: ['Inline/manual validation and framework coercion may not be recognized.'],
    }),
  );

  const rawSqlContexts = contexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'raw-sql'),
  );
  const rawSqlGaps = findingsByRule(findings, ['TW-AST004', 'TW-001']);
  controls.push(
    control({
      id: 'TW-CTRL-INJECTION-001',
      domain: 'input-validation',
      title: 'Raw SQL keeps request data out of query structure',
      status: rawSqlGaps.length
        ? 'GAP_CANDIDATE'
        : rawSqlContexts.length
          ? profilePartial
            ? 'PARTIAL'
            : 'UNVERIFIED'
          : noMappedApplicability,
      rationale: rawSqlGaps.length
        ? `${rawSqlGaps.length} raw SQL input-flow candidate(s) require review.`
        : rawSqlContexts.length
          ? `${rawSqlContexts.length} raw SQL boundary(s) were mapped, but source-only analysis did not establish effective parameterization.`
          : 'No supported raw SQL boundary was mapped.',
      applicability: 'Applies when mapped request/action code reaches raw SQL execution.',
      evidence: [
        ...references(
          'finding',
          rawSqlGaps.map((item) => item.id),
        ),
        ...contextEvidence(rawSqlContexts, ['raw-sql']),
        ...astRefs,
      ],
      verification:
        'Trace each query fragment, replace structural interpolation with parameters, and test metacharacter payloads without modifying production data.',
      limitations: [
        'Indirect builders, ORM-specific safe tagged templates, and database-side controls may require manual review.',
      ],
    }),
  );

  const commandContexts = contexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'command-execution'),
  );
  const commandGaps = findingsByRule(findings, ['TW-AST011']);
  controls.push(
    control({
      id: 'TW-CTRL-COMMAND-001',
      domain: 'input-validation',
      title: 'Process execution keeps request data out of commands and executable selection',
      status: commandGaps.length
        ? 'GAP_CANDIDATE'
        : commandContexts.length
          ? profilePartial
            ? 'PARTIAL'
            : 'UNVERIFIED'
          : noMappedApplicability,
      rationale: commandGaps.length
        ? `${commandGaps.length} request-to-process candidate(s) require review.`
        : commandContexts.length
          ? `${commandContexts.length} process execution boundary(s) were mapped without a decisive tainted flow.`
          : 'No supported process execution boundary was mapped.',
      applicability: 'Applies when mapped request/action code can start a local process.',
      evidence: [
        ...references(
          'finding',
          commandGaps.map((item) => item.id),
        ),
        ...contextEvidence(commandContexts, ['command-execution']),
        ...astRefs,
      ],
      verification:
        'Use fixed executables and argument arrays without a shell, then test separators, option injection, encoding, and unexpected executable names.',
    }),
  );

  const fileContexts = contexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'file-access'),
  );
  const pathGaps = findingsByRule(findings, ['TW-AST012']);
  controls.push(
    control({
      id: 'TW-CTRL-PATH-001',
      domain: 'input-validation',
      title: 'Filesystem paths remain inside server-owned roots',
      status: pathGaps.length
        ? 'GAP_CANDIDATE'
        : fileContexts.length
          ? profilePartial
            ? 'PARTIAL'
            : 'UNVERIFIED'
          : noMappedApplicability,
      rationale: pathGaps.length
        ? `${pathGaps.length} request-derived filesystem path candidate(s) require review.`
        : fileContexts.length
          ? `${fileContexts.length} filesystem boundary(s) were mapped without enough evidence to prove containment.`
          : 'No supported filesystem boundary was mapped.',
      applicability: 'Applies when mapped entry points read, write, rename, or delete local files.',
      evidence: [
        ...references(
          'finding',
          pathGaps.map((item) => item.id),
        ),
        ...contextEvidence(fileContexts, ['file-access']),
        ...astRefs,
      ],
      verification:
        'Test decoded parent traversal, absolute paths, separators, symlinks, and race conditions against the canonical storage root.',
    }),
  );

  const outboundContexts = contexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'outbound-request'),
  );
  const outboundGaps = findingsByRule(findings, ['TW-AST005']);
  controls.push(
    control({
      id: 'TW-CTRL-OUTBOUND-001',
      domain: 'integrations',
      title: 'Outbound destinations are server-owned or safely constrained',
      status: outboundGaps.length
        ? 'GAP_CANDIDATE'
        : outboundContexts.length
          ? profilePartial
            ? 'PARTIAL'
            : 'UNVERIFIED'
          : noMappedApplicability,
      rationale: outboundGaps.length
        ? `${outboundGaps.length} request-derived outbound destination candidate(s) require review.`
        : outboundContexts.length
          ? `${outboundContexts.length} outbound request boundary(s) were mapped without enough evidence to establish the effective network policy.`
          : 'No supported outbound request boundary was mapped.',
      applicability: 'Applies when mapped entry points can initiate server-side network requests.',
      evidence: [
        ...references(
          'finding',
          outboundGaps.map((item) => item.id),
        ),
        ...contextEvidence(outboundContexts, ['outbound-request']),
        ...astRefs,
      ],
      verification:
        'Test untrusted public, private, loopback, metadata, DNS-rebinding, and redirect destinations against the effective egress policy.',
      limitations: ['Network egress controls and DNS behavior are outside source-only evidence.'],
    }),
  );

  const redirectContexts = contexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'redirect'),
  );
  const redirectGaps = findingsByRule(findings, ['TW-AST006']);
  controls.push(
    control({
      id: 'TW-CTRL-REDIRECT-001',
      domain: 'integrations',
      title: 'Redirect destinations are constrained',
      status: redirectGaps.length
        ? 'GAP_CANDIDATE'
        : redirectContexts.length
          ? profilePartial
            ? 'PARTIAL'
            : 'UNVERIFIED'
          : noMappedApplicability,
      rationale: redirectGaps.length
        ? `${redirectGaps.length} request-derived redirect candidate(s) require review.`
        : redirectContexts.length
          ? `${redirectContexts.length} redirect boundary(s) were mapped without enough evidence to establish the effective destination policy.`
          : 'No supported redirect boundary was mapped.',
      applicability: 'Applies when mapped entry points construct a redirect response.',
      evidence: [
        ...references(
          'finding',
          redirectGaps.map((item) => item.id),
        ),
        ...contextEvidence(redirectContexts, ['redirect']),
        ...astRefs,
      ],
      verification:
        'Test external, scheme-relative, encoded, mixed-case, and userinfo-form destinations against the effective redirect policy.',
    }),
  );

  const uploadGaps = findingsByRule(findings, ['TW-AST007']);
  const httpEntrypoints = contexts.filter((context) =>
    ['next-route', 'next-pages-api', 'express-route'].includes(context.entrypoint.kind),
  );
  controls.push(
    control({
      id: 'TW-CTRL-UPLOAD-001',
      domain: 'input-validation',
      title: 'File uploads enforce size, content, and storage-path constraints',
      status: uploadGaps.length
        ? 'GAP_CANDIDATE'
        : httpEntrypoints.length
          ? profilePartial
            ? 'PARTIAL'
            : 'UNVERIFIED'
          : noMappedApplicability,
      rationale: uploadGaps.length
        ? `${uploadGaps.length} upload constraint candidate(s) require review.`
        : httpEntrypoints.length
          ? 'No decisive upload gap was mapped, but the profiler cannot prove that uploads are absent or fully constrained.'
          : 'No supported HTTP entry point was mapped.',
      applicability: 'Applies when an HTTP boundary accepts files or multipart form data.',
      evidence: [
        ...references(
          'finding',
          uploadGaps.map((item) => item.id),
        ),
        ...astRefs,
      ],
      verification:
        'Test byte limits, file count, MIME/content mismatch, polyglots, generated names, traversal, overwrite, and storage execution policy.',
      limitations: ['Streaming parsers and framework upload middleware may not be recognized.'],
    }),
  );

  const webhookVerified = webhooks.filter((context) =>
    context.facts.some((fact) => fact.kind === 'webhook-verification'),
  );
  const webhookGaps = findingsByRule(findings, ['TW-AST008']);
  controls.push(
    control({
      id: 'TW-CTRL-WEBHOOK-001',
      domain: 'integrations',
      title: 'Webhook authenticity is verified before processing',
      status: webhookGaps.length
        ? 'GAP_CANDIDATE'
        : webhooks.length
          ? profilePartial
            ? 'PARTIAL'
            : webhookVerified.length === webhooks.length
              ? 'EVIDENCED'
              : 'GAP_CANDIDATE'
          : noMappedApplicability,
      rationale: webhookGaps.length
        ? `${webhookGaps.length} webhook verification-order candidate(s) require review.`
        : webhooks.length
          ? `${webhookVerified.length} of ${webhooks.length} mapped webhook/callback boundary(s) contain a recognized signature or HMAC verification call.`
          : 'No supported webhook/callback boundary reaching a sensitive operation was mapped.',
      applicability: 'Applies to webhook/callback routes that reach sensitive operations.',
      evidence: [
        ...references(
          'finding',
          webhookGaps.map((item) => item.id),
        ),
        ...contextEvidence(webhookVerified, ['webhook-verification']),
      ],
      verification:
        'Send missing, invalid, replayed, and stale signatures and confirm rejection before parsing or persistence.',
      limitations: [
        'Provider SDK verification with an unrecognized function name may remain unverified.',
      ],
    }),
  );

  const webhookIdempotent = webhooks.filter((context) =>
    context.facts.some((fact) => fact.kind === 'idempotency'),
  );
  controls.push(
    control({
      id: 'TW-CTRL-SAAS-WEBHOOK-001',
      domain: 'integrations',
      title: 'Webhook side effects resist duplicate delivery',
      status: webhooks.length
        ? webhookIdempotent.length === webhooks.length
          ? profilePartial
            ? 'PARTIAL'
            : 'EVIDENCED'
          : 'GAP_CANDIDATE'
        : noMappedApplicability,
      rationale: webhooks.length
        ? `${webhookIdempotent.length} of ${webhooks.length} mapped webhook/callback boundary(s) contain a recognized idempotency claim or event-recording operation.`
        : 'No supported webhook/callback boundary reaching a sensitive operation was mapped.',
      applicability:
        'Applies to webhook/callback boundaries whose repeated delivery can persist data or repeat another sensitive effect.',
      evidence: [...contextEvidence(webhookIdempotent, ['idempotency']), ...saasRefs],
      verification:
        'Replay the same provider event concurrently and after a failure; confirm one durable effect and safe retry recovery.',
      limitations: [
        'Database uniqueness, queue deduplication, or provider infrastructure outside the mapped source may enforce replay safety.',
      ],
    }),
  );

  const highRiskRoute =
    /(?:login|sign[-_]?in|sign[-_]?up|register|password|reset|forgot|verify|otp|invite|checkout|billing)/i;
  const abuseSensitive = contexts.filter((context) =>
    highRiskRoute.test(
      `${context.entrypoint.route ?? ''} ${context.entrypoint.name} ${context.entrypoint.file}`,
    ),
  );
  const rateLimited = abuseSensitive.filter((context) =>
    context.facts.some((fact) => fact.kind === 'rate-limit'),
  );
  controls.push(
    control({
      id: 'TW-CTRL-SAAS-ABUSE-001',
      domain: 'authentication',
      title: 'Abuse-sensitive routes apply rate limits',
      status: abuseSensitive.length
        ? rateLimited.length === abuseSensitive.length
          ? profilePartial
            ? 'PARTIAL'
            : 'EVIDENCED'
          : 'GAP_CANDIDATE'
        : noMappedApplicability,
      rationale: abuseSensitive.length
        ? `${rateLimited.length} of ${abuseSensitive.length} mapped login, registration, recovery, invitation, verification, checkout, or billing boundary(s) contain a recognized rate-limit operation.`
        : 'No supported abuse-sensitive boundary was mapped.',
      applicability:
        'Applies to mapped authentication, account recovery, invitation, verification, checkout, and billing boundaries.',
      evidence: [...contextEvidence(rateLimited, ['rate-limit']), ...saasRefs],
      verification:
        'Burst requests by IP and account identifier, then confirm bounded retries, useful backoff, and no easy key rotation bypass.',
      limitations: [
        'Gateway, CDN, identity-provider, or distributed limiter enforcement outside the repository may remain unverified.',
      ],
    }),
  );

  const billingContexts = contexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'billing'),
  );
  const directlyInspectedBilling = billingContexts.filter((context) =>
    context.facts
      .filter((fact) => fact.kind === 'billing')
      .every((fact) => fact.file === context.entrypoint.file),
  );
  const billingGaps = findingsByRule(findings, ['TW-SAAS001']);
  controls.push(
    control({
      id: 'TW-CTRL-SAAS-BILLING-001',
      domain: 'authorization',
      title: 'Billing mutations derive charged values on the server',
      status: billingGaps.length
        ? 'GAP_CANDIDATE'
        : billingContexts.length
          ? saasRun?.status === 'completed' &&
            directlyInspectedBilling.length === billingContexts.length
            ? 'EVIDENCED'
            : saasRun?.status === 'failed'
              ? 'FAILED'
              : 'PARTIAL'
          : noMappedApplicability,
      rationale: billingGaps.length
        ? `${billingGaps.length} request-derived billing value candidate(s) require review.`
        : billingContexts.length
          ? `${billingContexts.length} billing mutation boundary(s) were mapped; ${directlyInspectedBilling.length} were directly inspected for request-derived price, product, plan, or amount fields.`
          : 'No supported billing-provider mutation was mapped.',
      applicability:
        'Applies to mapped checkout, payment-intent, subscription, invoice-item, refund, and transaction mutations.',
      evidence: [
        ...references(
          'finding',
          billingGaps.map((item) => item.id),
        ),
        ...contextEvidence(billingContexts, ['billing']),
        ...saasRefs,
      ],
      verification:
        'Tamper with plan, price, product, amount, currency, quantity, discount, and tenant ownership; compare the provider-side charge with the server catalog.',
      limitations: [
        'Billing calls reached through another function or package are structurally mapped, but client-value taint is not yet propagated into the dedicated SaaS rule.',
        'Business pricing rules, provider dashboard configuration, discounts, taxes, and webhook reconciliation remain outside source-only proof.',
      ],
    }),
  );

  const recoveryContexts = contexts.filter((context) =>
    /(?:password|reset|forgot|recovery|invite|verification|verify|otp)/i.test(
      `${context.entrypoint.route ?? ''} ${context.entrypoint.name} ${context.entrypoint.file}`,
    ),
  );
  const recoveryGaps = findingsByRule(findings, ['TW-SAAS003', 'TW-SAAS008', 'TW-SAAS009']);
  controls.push(
    control({
      id: 'TW-CTRL-SAAS-RECOVERY-001',
      domain: 'authentication',
      title: 'Recovery and invitation tokens have a bounded lifecycle',
      status: recoveryGaps.length
        ? 'GAP_CANDIDATE'
        : recoveryContexts.length
          ? saasRun?.status === 'failed'
            ? 'FAILED'
            : 'PARTIAL'
          : noMappedApplicability,
      rationale: recoveryGaps.length
        ? `${recoveryGaps.length} predictable, plaintext, or non-expiring token candidate(s) require review.`
        : recoveryContexts.length
          ? `${recoveryContexts.length} recovery, invitation, or verification boundary(s) were mapped without a decisive token-generation/storage candidate; atomic one-time use remains unverified.`
          : 'No supported recovery, invitation, or verification boundary was mapped.',
      applicability:
        'Applies to password recovery, invitations, email verification, unlock, magic-link, and OTP-style flows.',
      evidence: [
        ...references(
          'finding',
          recoveryGaps.map((item) => item.id),
        ),
        ...saasRefs,
      ],
      verification:
        'Test expiry, replay, concurrent redemption, account binding, user enumeration, token disclosure, and invalidation after password or email changes.',
      limitations: [
        'The mechanical scan cannot prove atomic consumption, delivery-channel security, or identity-provider policy.',
      ],
    }),
  );

  const oauthContexts = contexts.filter((context) =>
    /(?:oauth|oidc|openid|auth[/._-].*callback|callback[/._-].*auth)/i.test(
      `${context.entrypoint.route ?? ''} ${context.entrypoint.name} ${context.entrypoint.file}`,
    ),
  );
  const oauthGaps = findingsByRule(findings, ['TW-SAAS007']);
  controls.push(
    control({
      id: 'TW-CTRL-SAAS-OAUTH-001',
      domain: 'authentication',
      title: 'OAuth/OIDC flows bind redirects and authorization responses',
      status: oauthGaps.length
        ? 'GAP_CANDIDATE'
        : oauthContexts.length
          ? saasRun?.status === 'failed'
            ? 'FAILED'
            : 'UNVERIFIED'
          : noMappedApplicability,
      rationale: oauthGaps.length
        ? `${oauthGaps.length} request-derived OAuth redirect candidate(s) require review.`
        : oauthContexts.length
          ? `${oauthContexts.length} OAuth/OIDC-shaped boundary(s) were mapped; state, PKCE, nonce, redirect registration, and account-linking policy require explicit verification.`
          : 'No supported OAuth/OIDC boundary was mapped.',
      applicability:
        'Applies to OAuth/OIDC authorization initiation, callbacks, and account linking.',
      evidence: [
        ...references(
          'finding',
          oauthGaps.map((item) => item.id),
        ),
        ...saasRefs,
      ],
      verification:
        'Test missing/reused state, PKCE mismatch, nonce mismatch, redirect variants, login CSRF, account-link confusion, and authorization-code replay.',
      limitations: [
        'Provider SDK defaults and console-registered redirect URIs are external evidence.',
      ],
    }),
  );

  const tenantKeys = new Set(
    (profile?.saasSemantics?.vocabulary.tenantKeys ?? []).map((key) => key.toLowerCase()),
  );
  const resourceHelpers = new Set(
    (profile?.saasSemantics?.helpers.resourceScope ?? []).map((helper) => helper.toLowerCase()),
  );
  const tenantAware = Boolean(
    profile?.facts.some(
      (fact) =>
        fact.kind === 'resource-scope' &&
        (tenantKeys.has(fact.signal.toLowerCase()) ||
          resourceHelpers.has(fact.signal.toLowerCase())),
    ),
  );
  const databaseContexts = tenantAware
    ? sensitiveContexts.filter((context) =>
        context.facts.some((fact) => ['database', 'raw-sql'].includes(fact.kind)),
      )
    : [];
  const tenantScoped = databaseContexts.filter((context) =>
    context.facts.some(
      (fact) =>
        fact.kind === 'authorization' ||
        (fact.kind === 'resource-scope' &&
          (tenantKeys.has(fact.signal.toLowerCase()) ||
            resourceHelpers.has(fact.signal.toLowerCase()))),
    ),
  );
  const assignmentGaps = findingsByRule(findings, ['TW-SAAS002']);
  controls.push(
    control({
      id: 'TW-CTRL-SAAS-TENANT-001',
      domain: 'authorization',
      title: 'Tenant-aware data operations enforce a server-side scope',
      status: assignmentGaps.length
        ? 'GAP_CANDIDATE'
        : databaseContexts.length
          ? tenantScoped.length === databaseContexts.length
            ? profilePartial
              ? 'PARTIAL'
              : 'EVIDENCED'
            : 'GAP_CANDIDATE'
          : noMappedApplicability,
      rationale: assignmentGaps.length
        ? `${assignmentGaps.length} client-controlled ownership or privilege assignment candidate(s) require review.`
        : databaseContexts.length
          ? `${tenantScoped.length} of ${databaseContexts.length} mapped database boundary(s) in a tenant-aware project contain a recognized tenant scope or explicit authorization decision.`
          : 'No tenant-aware database boundary was established by the captured semantics and source.',
      applicability:
        'Applies after the profiler observes tenant vocabulary or a configured resource-scope helper at a database operation.',
      evidence: [
        ...references(
          'finding',
          assignmentGaps.map((item) => item.id),
        ),
        ...contextEvidence(tenantScoped, ['resource-scope', 'authorization']),
        ...saasRefs,
      ],
      verification:
        'Exercise every operation as two tenants, including list, lookup, update, delete, export, background job, and administrative paths; inspect effective RLS separately.',
      limitations: [
        'Row-level security and policy injected below the five-hop map can make an apparent gap safe.',
      ],
    }),
  );

  const cookieMutations = mutations.filter((context) =>
    context.facts.some((fact) => fact.kind === 'cookie'),
  );
  const csrfProtected = cookieMutations.filter((context) =>
    context.facts.some((fact) => fact.kind === 'csrf'),
  );
  controls.push(
    control({
      id: 'TW-CTRL-SAAS-CSRF-001',
      domain: 'browser-security',
      title: 'Cookie-authenticated mutations validate request origin or CSRF token',
      status: cookieMutations.length
        ? csrfProtected.length === cookieMutations.length
          ? profilePartial
            ? 'PARTIAL'
            : 'EVIDENCED'
          : 'GAP_CANDIDATE'
        : noMappedApplicability,
      rationale: cookieMutations.length
        ? `${csrfProtected.length} of ${cookieMutations.length} mapped cookie-using sensitive mutation boundary(s) contain a recognized CSRF or origin validation operation.`
        : 'No mapped sensitive mutation also contained a cookie operation.',
      applicability:
        'Applies when browsers automatically attach authentication cookies to state-changing HTTP requests.',
      evidence: [...contextEvidence(csrfProtected, ['csrf']), ...saasRefs],
      verification:
        'Send cross-site form, fetch, null-Origin, and sibling-subdomain requests; confirm rejection before the sensitive effect.',
      limitations: [
        'SameSite policy or centralized origin validation outside the mapped source may change applicability.',
      ],
    }),
  );

  const headerGaps = findingsByRule(findings, [
    'TW-P001',
    'TW-P002',
    'TW-H001',
    'TW-H002',
    'TW-H008',
  ]);
  const nextApplicable = Boolean(
    profile?.frameworks.some((framework) => framework.id.startsWith('nextjs')),
  );
  const runtimeHeaders = Boolean(
    httpProbe &&
    [
      'content-security-policy',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy',
    ].some((name) => httpProbe.headers[name]),
  );
  controls.push(
    control({
      id: 'TW-CTRL-HEADERS-001',
      domain: 'browser-security',
      title: 'Browser security policies are declared and observed',
      status: nextApplicable
        ? headerGaps.length
          ? 'GAP_CANDIDATE'
          : runtimeHeaders
            ? 'EVIDENCED'
            : postureRun?.status === 'failed'
              ? 'FAILED'
              : postureRun?.status === 'partial'
                ? 'PARTIAL'
                : 'UNVERIFIED'
        : noMappedApplicability,
      rationale: headerGaps.length
        ? `${headerGaps.length} header policy candidate(s) require review.`
        : runtimeHeaders
          ? 'The approved HTTP observation returned one or more selected browser security policy headers without a related probe finding.'
          : 'No effective runtime response was available to confirm browser policies.',
      applicability: 'Applies to mapped Next.js applications with browser-facing responses.',
      evidence: [
        ...references(
          'finding',
          headerGaps.map((item) => item.id),
        ),
        ...references('scanner', [postureRun?.id, httpRun?.id]),
        ...references('http-observation', runtimeHeaders ? [httpProbe?.finalUrl] : []),
      ],
      verification:
        'Observe representative production responses and verify CSP, frame, MIME, referrer, permissions, and transport policies.',
      limitations: [
        'One URL does not establish policy coverage for every route or deployment layer.',
      ],
    }),
  );

  const cookieGaps = findingsByRule(findings, ['TW-AST009', 'TW-P003', 'TW-H004']);
  const cookieFacts = contexts.flatMap((context) =>
    context.facts.filter((fact) => fact.kind === 'cookie'),
  );
  const authFacts = contexts.flatMap((context) =>
    context.facts.filter((fact) => fact.kind === 'authentication'),
  );
  controls.push(
    control({
      id: 'TW-CTRL-SESSION-001',
      domain: 'authentication',
      title: 'Sensitive cookies use explicit protection attributes',
      status: cookieGaps.length
        ? 'GAP_CANDIDATE'
        : cookieFacts.length && postureRun?.status === 'completed'
          ? 'EVIDENCED'
          : authFacts.length || cookieFacts.length
            ? 'UNVERIFIED'
            : noMappedApplicability,
      rationale: cookieGaps.length
        ? `${cookieGaps.length} sensitive cookie protection candidate(s) require review.`
        : cookieFacts.length
          ? `${cookieFacts.length} cookie operation(s) were mapped without a related deterministic candidate.`
          : 'No cookie-based session signal was mapped.',
      applicability: 'Applies when captured source uses cookie-based authentication/session state.',
      evidence: [
        ...references(
          'finding',
          cookieGaps.map((item) => item.id),
        ),
        ...references(
          'profile-fact',
          cookieFacts.map((item) => item.id),
        ),
        ...references('scanner', [postureRun?.id, httpRun?.id]),
      ],
      verification:
        'Inspect effective Set-Cookie attributes and test production HTTPS, expiry, logout, fixation, and CSRF behavior.',
    }),
  );

  const corsGaps = findingsByRule(findings, [
    'TW-P004',
    'TW-P005',
    'TW-H003',
    'TW-H006',
    'TW-H007',
  ]);
  const apiApplicable = contexts.some((context) =>
    ['next-route', 'next-pages-api', 'express-route', 'trpc-procedure'].includes(
      context.entrypoint.kind,
    ),
  );
  const observedCors = Boolean(httpProbe?.headers['access-control-allow-origin']);
  controls.push(
    control({
      id: 'TW-CTRL-CORS-001',
      domain: 'browser-security',
      title: 'Cross-origin access is intentionally constrained',
      status: apiApplicable
        ? corsGaps.length
          ? 'GAP_CANDIDATE'
          : observedCors
            ? 'EVIDENCED'
            : postureRun?.status === 'failed'
              ? 'FAILED'
              : 'UNVERIFIED'
        : noMappedApplicability,
      rationale: corsGaps.length
        ? `${corsGaps.length} broad or reflected CORS candidate(s) require review.`
        : observedCors
          ? 'An Access-Control-Allow-Origin policy was observed without a related probe candidate.'
          : 'No effective cross-origin policy was observed; same-origin-only operation is possible but unverified.',
      applicability: 'Applies to mapped HTTP API entry points.',
      evidence: [
        ...references(
          'finding',
          corsGaps.map((item) => item.id),
        ),
        ...references('scanner', [postureRun?.id, httpRun?.id]),
        ...references('http-observation', observedCors ? [httpProbe?.finalUrl] : []),
      ],
      verification:
        'Test trusted and untrusted Origin values, credential mode, preflight behavior, and server-side authorization independently.',
    }),
  );

  const secretGaps = findings.filter(
    (finding) =>
      finding.category === 'secrets' || ['TW-P010', 'TW-P011', 'TW-005'].includes(finding.ruleId),
  );
  controls.push(
    control({
      id: 'TW-CTRL-SECRETS-001',
      domain: 'secrets',
      title: 'Captured current source has no detected secret exposure candidate',
      status: secretGaps.length
        ? 'GAP_CANDIDATE'
        : gitleaksRun?.status === 'failed'
          ? 'FAILED'
          : gitleaksRun?.status === 'partial' || postureRun?.status === 'partial'
            ? 'PARTIAL'
            : gitleaksRun?.status === 'completed' && postureRun?.status === 'completed'
              ? 'EVIDENCED'
              : 'UNVERIFIED',
      rationale: secretGaps.length
        ? `${secretGaps.length} secret or client/server configuration candidate(s) require review.`
        : 'The result reflects only enabled scanners over the bounded current-source snapshot.',
      applicability: 'Applies to every captured repository.',
      evidence: [
        ...references(
          'finding',
          secretGaps.map((item) => item.id),
        ),
        ...references('scanner', [gitleaksRun?.id, postureRun?.id]),
      ],
      verification:
        'Review Git history, CI variables, deployment secrets, rotation, and provider-side secret scanning separately.',
      limitations: [
        historySecretsScanned
          ? 'Excluded working-tree credential files remain outside the snapshot. History matching does not validate credential activity.'
          : 'Excluded credential files and Git history are not scanned. No finding does not prove that no secret exists.',
      ],
    }),
  );

  const osvGaps = findings.filter((finding) => finding.source === 'osv');
  const resolvedDependencies = dependencies.filter((dependency) => dependency.resolvedVersion);
  controls.push(
    control({
      id: 'TW-CTRL-DEPS-001',
      domain: 'dependencies',
      title: 'Resolved dependencies are checked against OSV',
      status: resolvedDependencies.length
        ? osvGaps.length
          ? 'GAP_CANDIDATE'
          : osvRun?.status === 'failed'
            ? 'FAILED'
            : osvRun?.status === 'partial'
              ? 'PARTIAL'
              : osvRun?.status === 'completed'
                ? 'EVIDENCED'
                : 'UNVERIFIED'
        : noMappedApplicability,
      rationale: resolvedDependencies.length
        ? `${resolvedDependencies.length} resolved dependency record(s) were available; ${osvGaps.length} OSV finding(s) are attached.`
        : 'No supported resolved npm/pnpm/Yarn lockfile dependency was available.',
      applicability: 'Applies when supported lockfiles provide resolved npm ecosystem versions.',
      evidence: [
        ...references(
          'finding',
          osvGaps.map((item) => item.id),
        ),
        ...references('scanner', [osvRun?.id]),
      ],
      verification:
        'Review advisory freshness, runtime reachability, exploit preconditions, and supported upgrade paths.',
      limitations: ['Advisory presence does not establish reachability or exploitability.'],
    }),
  );

  const runtimeGaps = findings.filter((finding) => finding.source === 'http-probe');
  controls.push(
    control({
      id: 'TW-CTRL-RUNTIME-001',
      domain: 'runtime',
      title: 'Approved HTTP response posture is observed',
      status: runtimeGaps.length
        ? 'GAP_CANDIDATE'
        : httpRun?.status === 'failed'
          ? 'FAILED'
          : httpRun?.status === 'completed' && httpProbe
            ? 'EVIDENCED'
            : 'UNVERIFIED',
      rationale: httpProbe
        ? `${httpProbe.method} ${httpProbe.statusCode} was observed for one approved URL; ${runtimeGaps.length} runtime posture candidate(s) are attached.`
        : 'No target URL was explicitly approved for runtime observation.',
      applicability: 'Optional for any authorized running HTTP application.',
      evidence: [
        ...references(
          'finding',
          runtimeGaps.map((item) => item.id),
        ),
        ...references('scanner', [httpRun?.id]),
        ...references('http-observation', httpProbe ? [httpProbe.finalUrl] : []),
      ],
      verification:
        'Probe representative production routes and deployment layers under explicit authorization.',
      limitations: [
        'One bounded HEAD/GET observation is not DAST or whole-application runtime coverage.',
      ],
    }),
  );

  const logged = sensitiveContexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'logging'),
  );
  controls.push(
    control({
      id: 'TW-CTRL-LOGGING-001',
      domain: 'logging',
      title: 'Sensitive operations emit security-relevant audit events',
      status: sensitiveContexts.length
        ? logged.length === sensitiveContexts.length
          ? 'EVIDENCED'
          : logged.length
            ? 'PARTIAL'
            : 'UNVERIFIED'
        : noMappedApplicability,
      rationale: sensitiveContexts.length
        ? `${logged.length} of ${sensitiveContexts.length} mapped sensitive boundary(s) contain a recognized audit/security logging call.`
        : 'No supported sensitive operation boundary was mapped.',
      applicability:
        'Applies to authentication, authorization, administrative, data-changing, and integration-sensitive operations.',
      evidence: contextEvidence(logged, ['logging']),
      verification:
        'Confirm event content, actor, target, outcome, correlation ID, retention, access controls, and alerting in the real logging system.',
      limitations: [
        'Platform telemetry and logging wrappers with unrecognized names are outside source-only evidence.',
      ],
    }),
  );

  const handled = sensitiveContexts.filter((context) =>
    context.facts.some((fact) => fact.kind === 'error-handling'),
  );
  const exposedErrors = findingsByRule(findings, ['TW-SAAS004']);
  controls.push(
    control({
      id: 'TW-CTRL-ERRORS-001',
      domain: 'logging',
      title: 'Sensitive boundaries define explicit failure handling',
      status: exposedErrors.length
        ? 'GAP_CANDIDATE'
        : sensitiveContexts.length
          ? handled.length === sensitiveContexts.length
            ? 'EVIDENCED'
            : handled.length
              ? 'PARTIAL'
              : 'UNVERIFIED'
          : noMappedApplicability,
      rationale: exposedErrors.length
        ? `${exposedErrors.length} caught internal error response candidate(s) require review.`
        : sensitiveContexts.length
          ? `${handled.length} of ${sensitiveContexts.length} mapped sensitive boundary(s) contain an explicit catch clause within five call hops.`
          : 'No supported sensitive operation boundary was mapped.',
      applicability: 'Applies to mapped sensitive request/action boundaries.',
      evidence: [
        ...references(
          'finding',
          exposedErrors.map((item) => item.id),
        ),
        ...contextEvidence(handled, ['error-handling']),
        ...saasRefs,
      ],
      verification:
        'Exercise dependency, validation, authorization, and storage failures; confirm safe responses and useful internal diagnostics.',
      limitations: [
        'Framework-level error boundaries and centralized handlers may remain unverified.',
      ],
    }),
  );

  const nextCacheGaps = findingsByRule(findings, ['TW-NEXT003', 'TW-NEXT005', 'TW-H005']);
  controls.push(
    control({
      id: 'TW-CTRL-NEXT-001',
      domain: 'authorization',
      title: 'Next.js caching keeps user and tenant data isolated',
      status: nextApplicable
        ? gapStatus(nextCacheGaps, nextRun, profilePartial, nextRun?.status === 'completed')
        : noMappedApplicability,
      rationale: nextCacheGaps.length
        ? `${nextCacheGaps.length} user-specific function or response caching candidate(s) require review.`
        : 'No supported user-specific cache isolation candidate was found in the bounded Next.js scan.',
      applicability:
        'Applies to captured Next.js cache functions and authenticated route responses.',
      evidence: [
        ...references(
          'finding',
          nextCacheGaps.map((item) => item.id),
        ),
        ...references('scanner', [nextRun?.id]),
      ],
      verification:
        'Test two users or tenants against warm cache entries and inspect Cache-Control behavior at the deployed edge.',
      limitations: [
        'Runtime cache keys, CDN configuration, and reverse-proxy behavior remain outside source-only proof.',
      ],
    }),
  );

  const nextBoundaryGaps = findingsByRule(findings, ['TW-NEXT004', 'TW-NEXT007']);
  controls.push(
    control({
      id: 'TW-CTRL-NEXT-002',
      domain: 'secrets',
      title: 'Next.js client boundaries exclude privileged configuration and response data',
      status: nextApplicable
        ? gapStatus(nextBoundaryGaps, nextRun, profilePartial, nextRun?.status === 'completed')
        : noMappedApplicability,
      rationale: nextBoundaryGaps.length
        ? `${nextBoundaryGaps.length} public environment or sensitive response field candidate(s) require review.`
        : 'No supported privileged public environment or sensitive server response field candidate was found.',
      applicability:
        'Applies to NEXT_PUBLIC variables and captured Next.js server response objects.',
      evidence: [
        ...references(
          'finding',
          nextBoundaryGaps.map((item) => item.id),
        ),
        ...references('scanner', [nextRun?.id]),
      ],
      verification:
        'Inspect production client bundles, RSC payloads, and API responses for privileged values.',
    }),
  );

  const reactRenderingGaps = findingsByRule(findings, ['TW-REACT001']);
  controls.push(
    control({
      id: 'TW-CTRL-REACT-001',
      domain: 'input-validation',
      title: 'Dynamic HTML preserves React output encoding',
      status: gapStatus(
        reactRenderingGaps,
        reactRun,
        profilePartial,
        reactRun?.status === 'completed',
      ),
      rationale: reactRenderingGaps.length
        ? `${reactRenderingGaps.length} dynamic React HTML rendering candidate(s) require review.`
        : 'No unsanitized dynamic dangerouslySetInnerHTML candidate was found in the bounded React scan.',
      applicability: 'Applies to captured runtime JSX and TSX modules.',
      evidence: [
        ...references(
          'finding',
          reactRenderingGaps.map((item) => item.id),
        ),
        ...references('scanner', [reactRun?.id]),
      ],
      verification:
        'Test script, event-handler, URL, SVG, malformed markup, and mutation-XSS payloads at every intentional HTML rendering boundary.',
      limitations: [
        'Sanitizer policy configuration and browser mutation behavior require runtime review.',
      ],
    }),
  );

  const reactBrowserGaps = findingsByRule(findings, [
    'TW-REACT002',
    'TW-REACT003',
    'TW-REACT004',
    'TW-REACT005',
    'TW-REACT006',
  ]);
  controls.push(
    control({
      id: 'TW-CTRL-REACT-002',
      domain: 'browser-security',
      title: 'Client navigation, storage, and messaging use constrained browser boundaries',
      status: gapStatus(
        reactBrowserGaps,
        reactRun,
        profilePartial,
        reactRun?.status === 'completed',
      ),
      rationale: reactBrowserGaps.length
        ? `${reactBrowserGaps.length} client navigation, storage, messaging, or new-tab candidate(s) require review.`
        : 'No supported unsafe client URL, Web Storage, postMessage, or new-tab pattern was found.',
      applicability: 'Applies to explicit Client Component modules.',
      evidence: [
        ...references(
          'finding',
          reactBrowserGaps.map((item) => item.id),
        ),
        ...references('scanner', [reactRun?.id]),
      ],
      verification:
        'Exercise untrusted URLs, message origins, storage access after script injection, and external new-tab navigation.',
    }),
  );

  const reactBoundaryGaps = findingsByRule(findings, [
    'TW-REACT007',
    'TW-REACT008',
    'TW-REACT009',
    'TW-AST010',
  ]);
  controls.push(
    control({
      id: 'TW-CTRL-REACT-003',
      domain: 'secrets',
      title: 'Server and Client Component boundaries keep privileged data on the server',
      status: gapStatus(
        reactBoundaryGaps,
        reactRun,
        profilePartial,
        reactRun?.status === 'completed',
      ),
      rationale: reactBoundaryGaps.length
        ? `${reactBoundaryGaps.length} server/client boundary candidate(s) require review.`
        : 'No supported server-only import, sensitive prop, async Client Component, or private environment boundary candidate was found.',
      applicability: 'Applies to Next.js applications using React Server and Client Components.',
      evidence: [
        ...references(
          'finding',
          reactBoundaryGaps.map((item) => item.id),
        ),
        ...references('scanner', [reactRun?.id, astRun?.id]),
      ],
      verification:
        'Inspect serialized RSC payloads and production client bundles for credentials, privileged session objects, and server-only modules.',
    }),
  );

  const statuses: SecurityControlStatus[] = [
    'EVIDENCED',
    'GAP_CANDIDATE',
    'UNVERIFIED',
    'NOT_APPLICABLE',
    'PARTIAL',
    'FAILED',
  ];
  const summary = Object.fromEntries(
    statuses.map((status) => [
      status,
      controls.filter((controlResult) => controlResult.status === status).length,
    ]),
  ) as Record<SecurityControlStatus, number>;
  return {
    schemaVersion: 1,
    packId: 'traceward-web-application',
    packVersion: '0.5.0',
    controls,
    summary,
  };
}
