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
] as const;

interface ProbeResponse {
  statusCode: number;
  headers: IncomingHttpHeaders;
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
          'User-Agent': 'Traceward-Security-Probe/0.2',
          Connection: 'close',
        },
      },
      (response) => {
        let bytes = 0;
        response.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > responseLimitBytes) {
            response.destroy();
            fail('HTTP probe response exceeded its size limit.');
          }
        });
        response.on('error', () => fail('HTTP probe response failed.'));
        response.on('end', () => {
          if (settled) return;
          settled = true;
          resolve({ statusCode: response.statusCode ?? 0, headers: response.headers });
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
    let method: 'HEAD' | 'GET' = 'HEAD';
    let response: ProbeResponse;
    for (;;) {
      signal?.throwIfAborted();
      response = await requestOnce(target, method, timeoutMs, responseLimitBytes, signal);
      if ((response.statusCode === 405 || response.statusCode === 501) && method === 'HEAD') {
        method = 'GET';
        response = await requestOnce(target, method, timeoutMs, responseLimitBytes, signal);
      }
      const location = response.headers.location;
      if (![301, 302, 303, 307, 308].includes(response.statusCode) || !location) break;
      if (redirects >= redirectLimit) throw new Error('HTTP probe exceeded its redirect limit.');
      const redirected = new URL(Array.isArray(location) ? location[0] : location, target.url);
      target = await validateProbeUrl(redirected.toString(), options.allowPrivateNetwork, resolver);
      redirects++;
    }
    const observedAt = new Date().toISOString();
    const report: HttpProbeReport = {
      requestedUrl,
      finalUrl: target.displayUrl,
      method,
      statusCode: response.statusCode,
      redirects,
      observedAt,
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      headers: headerRecord(response.headers),
      cookies: cookieMetadata(response.headers),
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
        detail: `Observed one explicitly approved URL using ${method}, ${redirects} redirect(s), pinned validated DNS addresses, and bounded response handling. No crawl or exploit was attempted.`,
        version: '0.2.0',
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
        version: '0.2.0',
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
      version: '0.2.0',
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
