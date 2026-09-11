import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import type { IncomingHttpHeaders } from 'node:http';
import type { LookupFunction } from 'node:net';
import type {
  Evidence,
  Finding,
  HttpProbeOptions,
  HttpProbeReport,
  ScannerRun,
} from '../domain/types.ts';
import { digest, makeFinding } from '../domain/findings.ts';
import { redact } from '../security/redact.ts';
import {
  systemResolver,
  validateProbeUrl,
  type AddressResolver,
  type ValidatedProbeTarget,
} from '../security/url-policy.ts';

const retainedHeaders = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-frame-options',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'cross-origin-opener-policy',
  'cache-control',
  'vary',
  'content-type',
] as const;

const passiveProbeOrigin = 'https://codebasescan.invalid';

interface ProbeResponse {
  statusCode: number;
  headers: IncomingHttpHeaders;
  body?: string;
  bodyTruncated: boolean;
}

export interface HttpProbeResult {
  findings: Finding[];
  run: ScannerRun;
  report?: HttpProbeReport;
}

export interface ProbeRuntime {
  resolver?: AddressResolver;
  requestTimeoutMs?: number;
  responseLimitBytes?: number;
  redirectLimit?: number;
}

function pinnedLookup(address: string): LookupFunction {
  return ((
    _hostname: string,
    _options: unknown,
    callback: (error: NodeJS.ErrnoException | null, address: string, family: number) => void,
  ) => callback(null, address, isIP(address))) as unknown as LookupFunction;
}

async function requestOnce(
  target: ValidatedProbeTarget,
  method: 'HEAD' | 'GET',
  timeoutMs: number,
  responseLimitBytes: number,
  captureHtmlBody: boolean,
  signal?: AbortSignal,
): Promise<ProbeResponse> {
  const address = target.addresses[0];
  if (!address) throw new Error('HTTP probe target has no validated address.');
  const deadline = AbortSignal.timeout(timeoutMs);
  const requestSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (message: string) => {
      if (settled) return;
      settled = true;
      reject(new Error(message));
    };
    const transport = target.url.protocol === 'https:' ? httpsRequest : httpRequest;
    const request = transport(
      target.url,
      {
        method,
        signal: requestSignal,
        lookup: pinnedLookup(address.address),
        family: address.family,
        headers: {
          Accept: '*/*',
          Origin: passiveProbeOrigin,
          'User-Agent': 'CodebaseScan-Security-Probe/0.2',
          Connection: 'close',
        },
      },
      (response) => {
        let bytes = 0;
        const chunks: Buffer[] = [];
        const capturesBody =
          captureHtmlBody && /^text\/html\b/i.test(String(response.headers['content-type'] ?? ''));
        response.on('data', (value: Buffer | string) => {
          const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
          const remaining = responseLimitBytes - bytes;
          if (capturesBody && remaining > 0) chunks.push(chunk.subarray(0, remaining));
          bytes += chunk.length;
          if (bytes > responseLimitBytes) {
            if (capturesBody) {
              settled = true;
              resolve({
                statusCode: response.statusCode ?? 0,
                headers: response.headers,
                body: Buffer.concat(chunks).toString('utf8'),
                bodyTruncated: true,
              });
              response.destroy();
              return;
            }
            response.destroy();
            fail('HTTP probe response exceeded its size limit.');
          }
        });
        response.on('error', () => fail('HTTP probe response failed.'));
        response.on('end', () => {
          if (settled) return;
          settled = true;
          resolve({
            statusCode: response.statusCode ?? 0,
            headers: response.headers,
            ...(capturesBody ? { body: Buffer.concat(chunks).toString('utf8') } : {}),
            bodyTruncated: false,
          });
        });
      },
    );
    request.on('error', (error: NodeJS.ErrnoException) => {
      fail(
        error.name === 'AbortError'
          ? 'HTTP probe timed out or was cancelled.'
          : 'HTTP probe request failed.',
      );
    });
    request.end();
  });
}

function htmlAttribute(attributes: string, name: string): string | undefined {
  const match = new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(
    attributes,
  );
  return match?.[1] ?? match?.[2] ?? match?.[3];
}

function safeEndpoint(
  value: string | undefined,
  baseUrl: string,
): {
  action: string;
  relationship: 'same-origin' | 'cross-origin' | 'unresolved';
} {
  try {
    const base = new URL(baseUrl);
    const target = new URL(value?.trim() || baseUrl, base);
    if (!['http:', 'https:'].includes(target.protocol))
      return { action: '[unsupported form action]', relationship: 'unresolved' };
    target.username = '';
    target.password = '';
    target.search = '';
    target.hash = '';
    return {
      action: redact(target.toString()).slice(0, 500),
      relationship: target.origin === base.origin ? 'same-origin' : 'cross-origin',
    };
  } catch {
    return { action: '[unresolved form action]', relationship: 'unresolved' };
  }
}

function inspectHtmlSurface(
  html: string,
  contentType: string,
  baseUrl: string,
  bodyTruncated: boolean,
): NonNullable<HttpProbeReport['htmlSurface']> {
  const retained: NonNullable<HttpProbeReport['htmlSurface']>['formEndpoints'] = [];
  let formsObserved = 0;
  const formPattern = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi;
  for (const match of html.matchAll(formPattern)) {
    formsObserved++;
    if (retained.length >= 50) continue;
    const attributes = match[1] ?? '';
    const content = match[2] ?? '';
    const rawMethod = (htmlAttribute(attributes, 'method') ?? 'GET').toUpperCase();
    const method = ['GET', 'POST', 'DIALOG'].includes(rawMethod)
      ? (rawMethod as 'GET' | 'POST' | 'DIALOG')
      : 'UNKNOWN';
    const endpoint = safeEndpoint(htmlAttribute(attributes, 'action'), baseUrl);
    retained.push({
      method,
      ...endpoint,
      hasPassword: /<input\b[^>]*\btype\s*=\s*(?:"password"|'password'|password)(?:\s|\/?>)/i.test(
        content,
      ),
    });
  }
  return {
    contentType: redact(contentType).slice(0, 200),
    bodyTruncated,
    formsObserved,
    formsRetained: retained.length,
    formEndpoints: retained,
  };
}

function headerRecord(headers: IncomingHttpHeaders): Record<string, string> {
  return Object.fromEntries(
    retainedHeaders.flatMap((name) => {
      const value = headers[name];
      if (typeof value === 'string') return [[name, redact(value).slice(0, 2000)]];
      if (Array.isArray(value)) return [[name, redact(value.join(', ')).slice(0, 2000)]];
      return [];
    }),
  );
}

function cookieMetadata(headers: IncomingHttpHeaders): HttpProbeReport['cookies'] {
  const values = headers['set-cookie'] ?? [];
  const list = Array.isArray(values) ? values : [values];
  return list.slice(0, 30).map((value) => {
    const [pair = '', ...attributes] = value.split(';');
    const rawName = pair.split('=', 1)[0]?.trim() ?? '';
    const name = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(rawName) ? rawName : '[unnamed]';
    const normalized = attributes.map((item) => item.trim().toLowerCase());
    const sameSite = normalized.find((item) => item.startsWith('samesite='))?.slice(9);
    return {
      name,
      secure: normalized.includes('secure'),
      httpOnly: normalized.includes('httponly'),
      sameSite:
        sameSite === 'strict' || sameSite === 'lax' || sameSite === 'none'
          ? sameSite
          : 'unspecified',
    };
  });
}

function runtimeEvidence(report: HttpProbeReport, observation: string): Evidence {
  const excerpt = Object.entries(report.headers)
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');
  return {
    id: digest(`${report.finalUrl}:${report.observedAt}:${observation}`).slice(0, 16),
    kind: 'observed',
    file: 'runtime/http-response',
    startLine: 1,
    endLine: Math.max(1, excerpt.split('\n').length),
    excerpt: excerpt || '[No retained security headers observed]',
    fileDigest: digest(excerpt),
    observation,
    url: report.finalUrl,
    observedAt: report.observedAt,
  };
}

function normalizeFindings(report: HttpProbeReport): Finding[] {
  const findings: Finding[] = [];
  const headers = report.headers;
  const missing = [
    ...(!headers['content-security-policy'] ? ['Content-Security-Policy'] : []),
    ...(report.finalUrl.startsWith('https:') && !headers['strict-transport-security']
      ? ['Strict-Transport-Security']
      : []),
    ...(headers['x-content-type-options']?.toLowerCase() !== 'nosniff'
      ? ['X-Content-Type-Options: nosniff']
      : []),
    ...(!headers['referrer-policy'] ? ['Referrer-Policy'] : []),
    ...(!headers['permissions-policy'] ? ['Permissions-Policy'] : []),
    ...(!headers['content-security-policy']?.toLowerCase().includes('frame-ancestors') &&
    !['deny', 'sameorigin'].includes(headers['x-frame-options']?.toLowerCase() ?? '')
      ? ['frame protection']
      : []),
  ];
  if (missing.length)
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H001',
        title: 'Effective response security-header coverage is incomplete',
        category: 'configuration',
        severity: 'low',
        sourceSeverity: 'low',
        description: `The approved target response did not expose these effective policies: ${missing.join(', ')}. This observation applies only to the probed URL and time.`,
        remediation:
          'Define the missing headers at the application, proxy, CDN, or ingress layer and probe representative production routes again.',
        cwe: ['CWE-693'],
        evidence: [
          runtimeEvidence(
            report,
            `HTTP ${report.statusCode} response did not include expected policy: ${missing.join(', ')}.`,
          ),
        ],
      }),
    );
  if (/\bunsafe-eval\b/i.test(headers['content-security-policy'] ?? ''))
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H002',
        title: 'Effective Content Security Policy permits dynamic code evaluation',
        category: 'configuration',
        severity: 'medium',
        sourceSeverity: 'medium',
        description:
          "The approved target returned a Content-Security-Policy containing 'unsafe-eval'. The observation does not establish an exploitable injection path.",
        remediation:
          "Remove 'unsafe-eval' from the production policy where application behavior permits it.",
        cwe: ['CWE-693'],
        evidence: [runtimeEvidence(report, "The effective CSP contains 'unsafe-eval'.")],
      }),
    );
  if (
    headers['access-control-allow-origin'] === '*' &&
    headers['access-control-allow-credentials']?.toLowerCase() === 'true'
  )
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H003',
        title: 'Effective CORS policy combines wildcard origin and credentials',
        category: 'configuration',
        severity: 'high',
        sourceSeverity: 'high',
        description:
          'The approved target returned wildcard origin and credential support together. Browser enforcement and endpoint sensitivity still require contextual review.',
        remediation:
          'Return an exact validated origin for credentialed browser requests and enforce server-side authorization independently.',
        cwe: ['CWE-942'],
        evidence: [
          runtimeEvidence(
            report,
            'The effective response combined wildcard CORS with credentials.',
          ),
        ],
      }),
    );
  if (
    headers['access-control-allow-origin'] === report.probeOrigin &&
    headers['access-control-allow-credentials']?.toLowerCase() === 'true'
  )
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H006',
        title: 'Effective CORS policy reflects an untrusted origin with credentials',
        category: 'configuration',
        severity: 'high',
        sourceSeverity: 'high',
        description:
          'The approved target reflected CodebaseScan’s synthetic external Origin and allowed credentials. Endpoint sensitivity and browser behavior still require contextual review.',
        remediation:
          'Compare the Origin against an exact maintained allowlist before returning it, and enforce server-side authorization independently.',
        cwe: ['CWE-942'],
        evidence: [
          runtimeEvidence(
            report,
            `The response reflected ${report.probeOrigin} and allowed credentials.`,
          ),
        ],
      }),
    );
  if (
    headers['access-control-allow-origin'] === report.probeOrigin &&
    !headers.vary
      ?.split(',')
      .map((value) => value.trim().toLowerCase())
      .includes('origin')
  )
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H007',
        title: 'Reflected CORS response does not vary on Origin',
        category: 'configuration',
        severity: 'medium',
        sourceSeverity: 'medium',
        description:
          'The approved target reflected CodebaseScan’s synthetic external Origin without an observed Vary: Origin header. Shared caches can reuse an origin-specific response incorrectly.',
        remediation:
          'Return Vary: Origin whenever Access-Control-Allow-Origin changes by request, and verify intermediary cache behavior.',
        cwe: ['CWE-942', 'CWE-524'],
        evidence: [runtimeEvidence(report, 'The reflected CORS response omitted Vary: Origin.')],
      }),
    );
  const sensitiveCookies = report.cookies.filter((cookie) =>
    /(?:session|auth|token|jwt|sid)/i.test(cookie.name),
  );
  if (
    sensitiveCookies.length &&
    /(?:^|,)\s*public\b|\bs-maxage\s*=/i.test(headers['cache-control'] ?? '')
  )
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H005',
        title: 'Response setting a sensitive cookie permits shared caching',
        category: 'authorization',
        severity: 'high',
        sourceSeverity: 'high',
        description:
          'The approved response set a session- or token-shaped cookie while declaring public or shared cache semantics. Personalized response reuse remains a candidate until cache behavior is tested.',
        remediation:
          'Use private/no-store for personalized responses and verify CDN or reverse-proxy cache keys and bypass rules.',
        cwe: ['CWE-524'],
        evidence: [
          runtimeEvidence(
            report,
            `Shared cache policy was observed with sensitive cookie metadata: ${sensitiveCookies.map((cookie) => cookie.name).join(', ')}.`,
          ),
        ],
      }),
    );
  const contentSecurityPolicy = headers['content-security-policy'] ?? '';
  const scriptPolicy =
    /(?:^|;)\s*script-src\s+([^;]+)/i.exec(contentSecurityPolicy)?.[1] ??
    /(?:^|;)\s*default-src\s+([^;]+)/i.exec(contentSecurityPolicy)?.[1];
  if (
    scriptPolicy &&
    (/(?:^|\s)'unsafe-inline'(?:\s|$)/i.test(scriptPolicy) ||
      /(?:^|\s)\*(?:\s|$)/.test(scriptPolicy))
  )
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H008',
        title: 'Effective script policy allows broad inline or wildcard sources',
        category: 'configuration',
        severity: 'medium',
        sourceSeverity: 'medium',
        description:
          'The effective script/default CSP directive permits unsafe inline script or a wildcard source. This weakens mitigation but does not establish an injection path.',
        remediation:
          'Prefer nonces or hashes for necessary inline scripts and enumerate trusted script origins narrowly.',
        cwe: ['CWE-693'],
        evidence: [
          runtimeEvidence(report, `Effective script policy: ${scriptPolicy.slice(0, 500)}.`),
        ],
      }),
    );
  const downgrade = report.redirectChain?.find(
    (item) => item.from.startsWith('https:') && item.to.startsWith('http:'),
  );
  if (downgrade)
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H009',
        title: 'Observed redirect downgrades HTTPS to HTTP',
        category: 'configuration',
        severity: 'high',
        sourceSeverity: 'high',
        description:
          'The approved passive request crossed from HTTPS to cleartext HTTP during its redirect chain.',
        remediation: 'Keep every redirect hop on HTTPS and remove cleartext canonical targets.',
        cwe: ['CWE-319'],
        evidence: [
          runtimeEvidence(
            report,
            `Redirect downgrade observed from ${downgrade.from} to ${downgrade.to}.`,
          ),
        ],
      }),
    );
  for (const cookie of report.cookies) {
    if (!/(?:session|auth|token|jwt|sid)/i.test(cookie.name)) continue;
    if (cookie.secure && cookie.httpOnly && ['lax', 'strict'].includes(cookie.sameSite)) continue;
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H004',
        title: 'Observed sensitive cookie protection is incomplete',
        category: 'authentication',
        severity: 'high',
        sourceSeverity: 'high',
        description:
          'A session- or token-shaped Set-Cookie header lacked an expected Secure, HttpOnly, or SameSite protection. Cookie values were discarded.',
        remediation:
          'Set authentication cookies with Secure, HttpOnly, an explicit SameSite policy, constrained scope, and a bounded lifetime.',
        cwe: ['CWE-614', 'CWE-1004', 'CWE-1275'],
        evidence: [
          runtimeEvidence(
            report,
            `Cookie ${cookie.name} attributes: Secure=${cookie.secure}, HttpOnly=${cookie.httpOnly}, SameSite=${cookie.sameSite}. Value discarded.`,
          ),
        ],
      }),
    );
  }
  const forms = report.htmlSurface?.formEndpoints ?? [];
  const insecurePasswordForms = forms.filter(
    (form) => form.hasPassword && report.finalUrl.startsWith('http:'),
  );
  if (insecurePasswordForms.length)
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H010',
        title: 'Password form was observed on an HTTP page',
        category: 'authentication',
        severity: 'high',
        sourceSeverity: 'high',
        description:
          'The approved page contained a password input while the effective page URL used cleartext HTTP. Only retained form metadata was recorded.',
        remediation:
          'Serve the page and every submission target over HTTPS, then repeat the authorized runtime observation.',
        cwe: ['CWE-319'],
        evidence: [
          runtimeEvidence(
            report,
            `${insecurePasswordForms.length} password form(s) were observed on the HTTP page.`,
          ),
        ],
      }),
    );
  const passwordGetForms = forms.filter((form) => form.hasPassword && form.method === 'GET');
  if (passwordGetForms.length)
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H011',
        title: 'Password form submits with GET',
        category: 'privacy',
        severity: 'high',
        sourceSeverity: 'high',
        description:
          'The approved page contained a password input in a GET form. Submitted values can enter URLs, browser history, logs, and referrer data.',
        remediation:
          'Submit credentials only in a bounded HTTPS POST body and prevent URL logging.',
        cwe: ['CWE-598'],
        evidence: [
          runtimeEvidence(
            report,
            `Password GET form targets: ${passwordGetForms.map((form) => form.action).join(', ')}.`,
          ),
        ],
      }),
    );
  const crossOriginForms = forms.filter((form) => form.relationship === 'cross-origin');
  if (crossOriginForms.length)
    findings.push(
      makeFinding({
        source: 'http-probe',
        ruleId: 'TW-H012',
        title: 'Form submits to a different origin',
        category: 'privacy',
        severity: 'medium',
        sourceSeverity: 'medium',
        description:
          'The approved page contained a form whose action targets another origin. This can be intentional, but the data boundary and destination require review.',
        remediation:
          'Confirm the destination owner, submitted fields, consent, transport security, and redirect behavior before accepting the cross-origin transfer.',
        cwe: ['CWE-201', 'CWE-359'],
        evidence: [
          runtimeEvidence(
            report,
            `Cross-origin form targets: ${crossOriginForms.map((form) => form.action).join(', ')}.`,
          ),
        ],
      }),
    );
  return findings;
}

export async function probeHttp(
  options: HttpProbeOptions,
  signal?: AbortSignal,
  runtime: ProbeRuntime = {},
): Promise<HttpProbeResult> {
  const started = performance.now();
  const timeoutMs = Math.min(Math.max(runtime.requestTimeoutMs ?? 5000, 50), 15000);
  const responseLimitBytes = Math.min(
    Math.max(runtime.responseLimitBytes ?? 64 * 1024, 1024),
    256 * 1024,
  );
  const redirectLimit = Math.min(Math.max(runtime.redirectLimit ?? 3, 0), 5);
  const resolver = runtime.resolver ?? systemResolver;
  try {
    let target = await validateProbeUrl(options.url, options.allowPrivateNetwork, resolver);
    const requestedUrl = target.displayUrl;
    let redirects = 0;
    const redirectChain: NonNullable<HttpProbeReport['redirectChain']> = [];
    let method: 'HEAD' | 'GET' = 'HEAD';
    let response: ProbeResponse;
    for (;;) {
      signal?.throwIfAborted();
      response = await requestOnce(
        target,
        method,
        timeoutMs,
        responseLimitBytes,
        method === 'GET',
        signal,
      );
      if ((response.statusCode === 405 || response.statusCode === 501) && method === 'HEAD') {
        method = 'GET';
        continue;
      }
      const location = response.headers.location;
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && location) {
        if (redirects >= redirectLimit) throw new Error('HTTP probe exceeded its redirect limit.');
        const redirected = new URL(Array.isArray(location) ? location[0] : location, target.url);
        const nextTarget = await validateProbeUrl(
          redirected.toString(),
          options.allowPrivateNetwork,
          resolver,
        );
        redirectChain.push({
          statusCode: response.statusCode,
          from: target.displayUrl,
          to: nextTarget.displayUrl,
        });
        target = nextTarget;
        redirects++;
        continue;
      }
      if (
        method === 'HEAD' &&
        /^text\/html\b/i.test(String(response.headers['content-type'] ?? ''))
      ) {
        method = 'GET';
        continue;
      }
      break;
    }
    const observedAt = new Date().toISOString();
    const report: HttpProbeReport = {
      requestedUrl,
      finalUrl: target.displayUrl,
      method,
      statusCode: response.statusCode,
      redirects,
      redirectChain,
      probeOrigin: passiveProbeOrigin,
      observedAt,
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      headers: headerRecord(response.headers),
      cookies: cookieMetadata(response.headers),
      ...(response.body !== undefined
        ? {
            htmlSurface: inspectHtmlSurface(
              response.body,
              String(response.headers['content-type'] ?? 'text/html'),
              target.displayUrl,
              response.bodyTruncated,
            ),
          }
        : {}),
    };
    const findings = normalizeFindings(report);
    return {
      findings,
      report,
      run: {
        id: 'http-probe',
        name: 'HTTP runtime posture',
        status: 'completed',
        durationMs: report.durationMs,
        findings: findings.length,
        detail: `Observed one explicitly approved URL using ${method}, ${redirects} redirect(s), pinned validated DNS addresses, bounded response handling, and ${report.htmlSurface?.formsObserved ?? 0} retained-page form observation(s). No crawl or exploit was attempted.`,
        version: '0.4.0',
      },
    };
  } catch (error) {
    return {
      findings: [],
      run: {
        id: 'http-probe',
        name: 'HTTP runtime posture',
        status: 'failed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: `Probe did not complete: ${redact(error instanceof Error ? error.message : 'unknown failure')}`,
        version: '0.4.0',
      },
    };
  }
}

export function skippedHttpProbe(): HttpProbeResult {
  return {
    findings: [],
    run: {
      id: 'http-probe',
      name: 'HTTP runtime posture',
      status: 'skipped',
      durationMs: 0,
      findings: 0,
      detail: 'Not run. No HTTP target was explicitly approved for this audit.',
      version: '0.4.0',
    },
  };
}

export function reconcileHttpPosture(findings: Finding[], report?: HttpProbeReport): Finding[] {
  if (!report) return findings;
  const pairs: Record<string, string> = {
    'TW-H001': 'TW-P001',
    'TW-H002': 'TW-P002',
    'TW-H003': 'TW-P004',
    'TW-H004': 'TW-P003',
    'TW-H005': 'TW-NEXT005',
    'TW-H006': 'TW-P005',
    'TW-H007': 'TW-P005',
    'TW-H008': 'TW-P002',
  };
  const runtime = findings.filter((item) => item.source === 'http-probe');
  const consumed = new Set<string>();
  const reconciled = findings
    .filter((item) => item.source !== 'http-probe')
    .map((item) => {
      const match = runtime.find((candidate) => pairs[candidate.ruleId] === item.ruleId);
      if (match) {
        consumed.add(match.id);
        return {
          ...item,
          evidence: [...item.evidence, ...match.evidence],
          runtimeVerification: {
            status: 'corroborated' as const,
            observation:
              'The approved runtime response corroborated the related static posture candidate.',
            url: report.finalUrl,
            observedAt: report.observedAt,
          },
        };
      }
      if (item.source === 'posture' && Object.values(pairs).includes(item.ruleId))
        return {
          ...item,
          runtimeVerification: {
            status: 'observed_safe' as const,
            observation:
              'The related weakness was not observed in this single approved HTTP response. The static declaration candidate remains for review because routes and environments can differ.',
            url: report.finalUrl,
            observedAt: report.observedAt,
          },
        };
      return item;
    });
  return [...reconciled, ...runtime.filter((item) => !consumed.has(item.id))];
}
