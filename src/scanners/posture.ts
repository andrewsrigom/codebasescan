import type { Category, Finding, Severity, Snapshot, SourceFile } from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';

interface Candidate {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  description: string;
  remediation: string;
  cwe: string[];
  file: SourceFile;
  index: number;
  observation: string;
  hideExcerpt?: boolean;
}

const sourceFile = /\.(?:[cm]?[jt]sx?)$/;
const configFile =
  /(?:^|\/)(?:next\.config\.[cm]?[jt]s|vercel\.json|middleware\.[cm]?[jt]s|proxy\.[cm]?[jt]s)$/;
const routeFile = /(?:^|\/)app\/api\/.+\/route\.[cm]?[jt]s$/;
const sensitiveOperation =
  /\b(?:create|update|delete|remove|destroy|insert|upsert|findUnique|execute|refund|billing|payment|admin)\b|\b(?:prisma|database|db)\s*\./i;
const authenticationSignal =
  /\b(?:auth|authenticate|requireSession|getServerSession|currentUser|verifyToken|validateSession|withAuth)\s*\(/i;
const authorizationSignal =
  /\b(?:authorize|requireRole|hasPermission|assertAccess|canAccess|tenantId|ownerId|userId\s*:)\b/i;

function lineAt(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

function finding(candidate: Candidate): Finding {
  const evidence = sourceEvidence(
    candidate.file,
    lineAt(candidate.file.content, candidate.index),
    candidate.observation,
  );
  evidence.kind = 'declared';
  if (candidate.hideExcerpt) evidence.excerpt = '[Sensitive configuration value withheld]';
  return makeFinding({
    source: 'posture',
    ruleId: candidate.ruleId,
    title: candidate.title,
    category: candidate.category,
    severity: candidate.severity,
    sourceSeverity: candidate.severity,
    description: candidate.description,
    remediation: candidate.remediation,
    cwe: candidate.cwe,
    evidence: [evidence],
  });
}

function nextProject(snapshot: Snapshot): boolean {
  return snapshot.files.some(
    (file) =>
      /^next\.config\./.test(file.path.split('/').at(-1) ?? '') ||
      (file.path.endsWith('package.json') && /["']next["']\s*:/.test(file.content)),
  );
}

function globalAuthCoverage(snapshot: Snapshot): boolean {
  return snapshot.files.some(
    (file) =>
      /(?:^|\/)(?:middleware|proxy)\.[cm]?[jt]s$/.test(file.path) &&
      authenticationSignal.test(file.content) &&
      /matcher\s*:\s*(?:\[[^\]]*\/api|["']\/api)/s.test(file.content),
  );
}

function headerCandidates(snapshot: Snapshot): Candidate[] {
  if (!nextProject(snapshot)) return [];
  const files = snapshot.files.filter((file) => configFile.test(file.path));
  if (!files.length) return [];
  const joined = files.map((file) => file.content.toLowerCase()).join('\n');
  const requirements = [
    ['Content-Security-Policy', /content-security-policy/],
    ['Strict-Transport-Security', /strict-transport-security/],
    ['X-Content-Type-Options', /x-content-type-options/],
    ['Referrer-Policy', /referrer-policy/],
    ['Permissions-Policy', /permissions-policy/],
  ] as const;
  const missing: string[] = requirements
    .filter(([, pattern]) => !pattern.test(joined))
    .map(([name]) => name);
  if (!/frame-ancestors|x-frame-options/.test(joined)) missing.push('frame protection');
  const candidates: Candidate[] = [];
  if (missing.length) {
    const file = files[0]!;
    candidates.push({
      ruleId: 'TW-P001',
      title: 'Declared response security-header coverage is incomplete',
      category: 'configuration',
      severity: 'low',
      description: `Traceward could not find these declarations in the captured Next.js, proxy, or deployment configuration: ${missing.join(', ')}. A CDN, ingress, framework default, or production-only layer outside this snapshot may still provide them.`,
      remediation:
        'Confirm the effective production response headers. Define missing policy at one authoritative layer and use the opt-in HTTP probe to verify what reaches a browser.',
      cwe: ['CWE-693'],
      file,
      index: 0,
      observation:
        'One or more recommended browser security policies were not found across the captured configuration sources. This is a coverage candidate, not proof that the runtime response is unsafe.',
    });
  }
  for (const file of files) {
    for (const match of file.content.matchAll(/content-security-policy[\s\S]{0,500}?unsafe-eval/gi))
      candidates.push({
        ruleId: 'TW-P002',
        title: 'Content Security Policy permits dynamic code evaluation',
        category: 'configuration',
        severity: 'medium',
        description:
          "A declared Content-Security-Policy appears to include 'unsafe-eval'. Some development tooling requires this, so the effective production policy still needs verification.",
        remediation:
          "Remove 'unsafe-eval' from the production script policy where possible and validate the effective policy against required application behavior.",
        cwe: ['CWE-693'],
        file,
        index: match.index,
        observation: "The captured configuration places 'unsafe-eval' near a CSP declaration.",
      });
  }
  return candidates;
}

function callSlice(content: string, start: number): string {
  const bounded = content.slice(start, start + 1400);
  const end = bounded.search(/\)\s*;|\n\s*\}/);
  return bounded.slice(0, end < 0 ? bounded.length : end + 1);
}

function cookieCandidates(snapshot: Snapshot): Candidate[] {
  const candidates: Candidate[] = [];
  const cookieCall = /(?:cookies\s*\(\s*\)\s*\.set|response\.cookies\.set|res\.cookie)\s*\(/gi;
  for (const file of snapshot.files.filter((entry) => sourceFile.test(entry.path))) {
    for (const match of file.content.matchAll(cookieCall)) {
      const call = callSlice(file.content, match.index);
      const sensitiveName =
        /["'`](?:__Host-|__Secure-)?[^"'`]*(?:session|auth|access[_-]?token|refresh[_-]?token|jwt|sid)[^"'`]*["'`]/i.test(
          call,
        );
      if (!sensitiveName) continue;
      const httpOnly = /httpOnly\s*:\s*true/i.test(call);
      const secure =
        /secure\s*:\s*true/i.test(call) ||
        /secure\s*:\s*[^,\n]*(?:NODE_ENV|production)/i.test(call) ||
        /__Host-|__Secure-/i.test(call);
      const sameSite = /sameSite\s*:\s*["'`](?:strict|lax)["'`]/i.test(call);
      if (httpOnly && secure && sameSite) continue;
      const missing = [
        ...(!httpOnly ? ['HttpOnly'] : []),
        ...(!secure ? ['Secure'] : []),
        ...(!sameSite ? ['SameSite=Lax or Strict'] : []),
      ];
      candidates.push({
        ruleId: 'TW-P003',
        title: 'Sensitive cookie protection is incomplete',
        category: 'authentication',
        severity: 'high',
        description: `A session- or token-shaped cookie declaration lacks an obvious ${missing.join(', ')} setting. The scanner cannot determine controls added by a wrapper or upstream framework.`,
        remediation:
          'For authentication cookies, use HttpOnly and Secure in production, choose an explicit SameSite policy, limit path/domain and lifetime, and document any intentional client access.',
        cwe: ['CWE-614', 'CWE-1004', 'CWE-1275'],
        file,
        index: match.index,
        observation: `Sensitive cookie declaration did not visibly set: ${missing.join(', ')}.`,
      });
    }
  }
  return candidates;
}

function corsCandidates(snapshot: Snapshot): Candidate[] {
  const candidates: Candidate[] = [];
  for (const file of snapshot.files.filter((entry) => sourceFile.test(entry.path))) {
    const content = file.content;
    const wildcard = /access-control-allow-origin["'`]?[\s]*[:,][\s]*["'`]\*["'`]/i.exec(content);
    const credentials =
      /access-control-allow-credentials["'`]?[\s]*[:,][\s]*(?:["'`]true["'`]|true)/i.test(content);
    const sensitiveApi = routeFile.test(file.path) && sensitiveOperation.test(content);
    if (wildcard && (credentials || sensitiveApi))
      candidates.push({
        ruleId: 'TW-P004',
        title: 'Broad CORS origin is applied to a sensitive API',
        category: 'configuration',
        severity: credentials ? 'high' : 'medium',
        description:
          'A wildcard Access-Control-Allow-Origin policy appears on a credentialed or sensitive API path. CORS does not replace server-side authorization.',
        remediation:
          'Allow only intended browser origins, keep credential behavior explicit, and enforce authentication and authorization independently of Origin.',
        cwe: ['CWE-942'],
        file,
        index: wildcard.index,
        observation: `Wildcard CORS was found${credentials ? ' together with credential support' : ' on a route with sensitive operations'}.`,
      });
    const reflection =
      /access-control-allow-origin["'`]?[\s]*[:,][\s]*(?:request\.)?headers(?:\.get|\[)\s*\(?["'`]origin/i.exec(
        content,
      );
    if (
      reflection &&
      !/(?:allowedOrigins|originAllowlist|trustedOrigins)\s*\.\s*(?:has|includes)\s*\(/i.test(
        content,
      )
    )
      candidates.push({
        ruleId: 'TW-P005',
        title: 'CORS origin appears to be reflected without an allowlist',
        category: 'configuration',
        severity: 'high',
        description:
          'The request Origin appears to be copied into Access-Control-Allow-Origin without a visible allowlist check in the same file.',
        remediation:
          'Normalize the origin and compare it against an exact server-controlled allowlist before returning it. Reject untrusted origins.',
        cwe: ['CWE-942'],
        file,
        index: reflection.index,
        observation:
          'Request Origin is used in the response CORS policy without a nearby allowlist signal.',
      });
  }
  return candidates;
}

function authorizationCandidates(snapshot: Snapshot): Candidate[] {
  const candidates: Candidate[] = [];
  const middlewareCovered = globalAuthCoverage(snapshot);
  for (const file of snapshot.files.filter((entry) => sourceFile.test(entry.path))) {
    const content = file.content;
    if (
      routeFile.test(file.path) &&
      /export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b/.test(content)
    ) {
      if (
        sensitiveOperation.test(content) &&
        !authenticationSignal.test(content) &&
        !middlewareCovered
      )
        candidates.push({
          ruleId: 'TW-P006',
          title: 'Sensitive API mutation has no visible authentication guard',
          category: 'authorization',
          severity: 'high',
          description:
            'A mutating API route performs a sensitive operation without an obvious authentication call in the file or captured global API middleware. Custom wrappers may be outside this heuristic.',
          remediation:
            'Require an authenticated principal at the route boundary, then enforce action- and object-level authorization close to the operation. Add unauthenticated regression tests.',
          cwe: ['CWE-306', 'CWE-862'],
          file,
          index: content.search(/export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b/),
          observation:
            'A mutating route and sensitive operation were found without a recognized authentication signal.',
        });
      const idLookup = /\.findUnique\s*\(\s*\{\s*where\s*:\s*\{\s*id(?:\s*[,}]|\s*:)/s.exec(
        content,
      );
      if (idLookup && !authorizationSignal.test(content))
        candidates.push({
          ruleId: 'TW-P007',
          title: 'Object lookup has no visible ownership or tenant constraint',
          category: 'authorization',
          severity: 'high',
          description:
            'A route looks up an object by identifier without a visible tenant, owner, role, or policy check in the same file. Middleware or database policy may still enforce access.',
          remediation:
            'Bind the query or an explicit authorization decision to the authenticated tenant/owner and test cross-tenant identifiers.',
          cwe: ['CWE-639', 'CWE-862'],
          file,
          index: idLookup.index,
          observation:
            'Identifier-only lookup has no recognized object-authorization signal in this route.',
        });
      if (/\/(?:admin|internal)\//i.test(file.path) && !authorizationSignal.test(content))
        candidates.push({
          ruleId: 'TW-P008',
          title: 'Administrative route has no visible role or permission check',
          category: 'authorization',
          severity: 'high',
          description:
            'A mutating admin/internal route lacks an obvious role, permission, tenant, or policy decision in the same file. Path naming alone is not a security boundary.',
          remediation:
            'Enforce an explicit server-side permission check for every administrative action and test authenticated non-admin access.',
          cwe: ['CWE-862'],
          file,
          index: content.search(/export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b/),
          observation: 'A privileged-looking route has no recognized authorization signal.',
        });
    }
    if (
      /^[\s\S]{0,200}["']use server["'];?/m.test(content) &&
      /export\s+(?:async\s+)?function\b/.test(content) &&
      sensitiveOperation.test(content) &&
      !authenticationSignal.test(content)
    )
      candidates.push({
        ruleId: 'TW-P009',
        title: 'Sensitive server action has no visible authentication guard',
        category: 'authorization',
        severity: 'high',
        description:
          'A server action appears to perform a sensitive operation without a recognized authentication check in the same module. Client-side visibility and form controls are not authorization.',
        remediation:
          'Authenticate and authorize inside the server action or a trusted server-only function it calls. Add direct invocation tests for unauthenticated and unauthorized users.',
        cwe: ['CWE-306', 'CWE-862'],
        file,
        index: content.search(/export\s+(?:async\s+)?function\b/),
        observation:
          'A server action and sensitive operation were found without a recognized authentication signal.',
      });
  }
  return candidates;
}

function environmentCandidates(snapshot: Snapshot): Candidate[] {
  const candidates: Candidate[] = [];
  for (const file of snapshot.files.filter((entry) => sourceFile.test(entry.path))) {
    const client = /^[\s\S]{0,200}["']use client["'];?/m.test(file.content);
    if (client) {
      for (const match of file.content.matchAll(
        /process\.env\.([A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE_KEY|SERVICE_ROLE|DATABASE_URL)[A-Z0-9_]*)/g,
      ))
        candidates.push({
          ruleId: 'TW-P010',
          title: 'Client module references sensitive server configuration',
          category: 'secrets',
          severity: 'high',
          description:
            'A client-designated module references a sensitive-looking environment variable. Bundler behavior and actual exposure require verification; the value is not included in this report.',
          remediation:
            'Move privileged configuration and dependent logic into a server-only module. Expose only the minimum non-sensitive result through an authenticated boundary.',
          cwe: ['CWE-200'],
          file,
          index: match.index,
          observation: `Client module references sensitive-looking environment name ${match[1]}. No value was read.`,
          hideExcerpt: true,
        });
    }
    for (const match of file.content.matchAll(
      /process\.env\.([A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE_KEY|SERVICE_ROLE|DATABASE_URL)[A-Z0-9_]*)\s*(?:\|\||\?\?)\s*["'`]([^"'`\r\n]+)["'`]/g,
    )) {
      const fallback = match[2] ?? '';
      if (!fallback || /^(?:test|fixture|example|changeme)$/i.test(fallback)) continue;
      candidates.push({
        ruleId: 'TW-P011',
        title: 'Sensitive configuration has a non-empty fallback value',
        category: 'secrets',
        severity: 'high',
        description:
          'A sensitive-looking environment variable has a literal fallback. This can turn missing production configuration into a predictable credential or connection setting. The fallback is withheld.',
        remediation:
          'Fail closed when required secrets are missing. Keep non-production defaults isolated in explicit test configuration and never reuse them in deployments.',
        cwe: ['CWE-798', 'CWE-1188'],
        file,
        index: match.index,
        observation: `Sensitive-looking environment name ${match[1]} has a non-empty literal fallback. The value was not retained.`,
        hideExcerpt: true,
      });
    }
  }
  return candidates;
}

export function scanPosture(snapshot: Snapshot): Finding[] {
  return [
    ...headerCandidates(snapshot),
    ...cookieCandidates(snapshot),
    ...corsCandidates(snapshot),
    ...authorizationCandidates(snapshot),
    ...environmentCandidates(snapshot),
  ]
    .slice(0, 300)
    .map(finding);
}
