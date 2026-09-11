import ts from 'typescript';
import type { Category, Finding, Severity, Snapshot } from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import { isRuntimeSource } from '../security/paths.ts';
interface Rule {
  id: string;
  title: string;
  pattern: RegExp;
  severity: Severity;
  category: Category;
  description: string;
  remediation: string;
  cwe: string[];
}
export const rules: Rule[] = [
  {
    id: 'TW-001',
    title: 'Raw SQL execution needs input tracing',
    pattern: /\$queryRawUnsafe\s*\(/g,
    severity: 'high',
    category: 'injection',
    cwe: ['CWE-89'],
    description:
      'An unsafe SQL execution API is present. User control of the query and runtime reachability have not been established.',
    remediation:
      'Prefer parameterized queries. Trace every value reaching this call before deciding whether an injection vulnerability exists.',
  },
  {
    id: 'TW-002',
    title: 'HTML rendering bypass needs sanitization review',
    pattern: /dangerouslySetInnerHTML\s*=/g,
    severity: 'medium',
    category: 'injection',
    cwe: ['CWE-79'],
    description:
      'Raw HTML reaches a React rendering sink. The scanner does not prove that the value is attacker-controlled or unsanitized.',
    remediation:
      'Establish the source of the HTML and verify an appropriate sanitizer. Prefer rendering text when rich HTML is unnecessary.',
  },
  {
    id: 'TW-003',
    title: 'Dynamic code execution needs trust-boundary review',
    pattern: /(?:(?<![\w$.])eval\s*\(|\b(?:globalThis|window)\.eval\s*\(|\bnew\s+Function\s*\()/g,
    severity: 'high',
    category: 'code',
    cwe: ['CWE-95'],
    description:
      'A dynamic execution sink was detected. This is a pattern match, not proof of attacker-controlled execution.',
    remediation:
      'Replace dynamic code execution with explicit operations where possible; otherwise document and enforce the trust boundary.',
  },
  {
    id: 'TW-004',
    title: 'Object lookup needs tenant authorization review',
    pattern: /\.findUnique\s*\(\s*\{\s*where\s*:\s*\{\s*id(?:\s*[,}]|\s*:)/g,
    severity: 'medium',
    category: 'authorization',
    cwe: ['CWE-639'],
    description:
      'An object lookup begins with an ID filter. This is a review hotspot, not evidence of a missing authorization check; inspect middleware, service policy, RLS and the complete call path.',
    remediation:
      'Verify object-level access for the authenticated tenant. Add a regression test using two tenants and reject cross-tenant access.',
  },
  {
    id: 'TW-005',
    title: 'Sensitive configuration uses a public environment name',
    pattern: /NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|SERVICE_ROLE)[A-Z0-9_]*/g,
    severity: 'high',
    category: 'secrets',
    cwe: ['CWE-200'],
    description:
      'A sensitive-looking setting has a browser-public naming convention. No active credential or actual browser bundle exposure has been verified.',
    remediation:
      'Keep privileged credentials in server-only configuration. If exposure is verified, rotate the credential and review its use.',
  },
  {
    id: 'TW-006',
    title: 'Wildcard cross-origin policy needs context review',
    pattern: /["']Access-Control-Allow-Origin["']\s*[:,]\s*["']\*["']/gi,
    severity: 'medium',
    category: 'configuration',
    cwe: ['CWE-942'],
    description:
      'A wildcard CORS origin was found. Public endpoints may intentionally permit it; authentication and exposed data determine the risk.',
    remediation:
      'Define expected browser origins and validate the credential model. Do not treat CORS as an authorization mechanism.',
  },
  {
    id: 'TW-007',
    title: 'Destructive agent tool needs permission review',
    pattern: /tools\s*:\s*\[[^\]]*\b(?:deleteUser|issueRefund|deleteFile)\b/g,
    severity: 'high',
    category: 'ai-security',
    cwe: ['CWE-862'],
    description:
      'A potentially destructive operation appears in an agent tool list. The pattern cannot determine whether approval and authorization are enforced inside the tool.',
    remediation:
      'Apply authorization inside each tool, restrict its capability, and require explicit approval where the operation warrants it.',
  },
];

function commentRanges(content: string, filePath: string): { start: number; end: number }[] {
  const source = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true);
  const ranges: { start: number; end: number }[] = [];
  const seen = new Set<string>();
  const collect = (position: number): void => {
    const comments = [
      ...(ts.getLeadingCommentRanges(content, position) ?? []),
      ...(ts.getTrailingCommentRanges(content, position) ?? []),
    ];
    for (const comment of comments) {
      const key = `${comment.pos}:${comment.end}`;
      if (seen.has(key)) continue;
      seen.add(key);
      ranges.push({ start: comment.pos, end: comment.end });
    }
  };
  const visit = (node: ts.Node): void => {
    collect(node.pos);
    collect(node.end);
    ts.forEachChild(node, visit);
  };
  visit(source);
  return ranges;
}

function insideComment(index: number, ranges: { start: number; end: number }[]): boolean {
  return ranges.some((range) => index >= range.start && index < range.end);
}

export function scanPatterns(snapshot: Snapshot): Finding[] {
  const findings: Finding[] = [];
  for (const file of snapshot.files) {
    if (!isRuntimeSource(file) || !/\.(?:[cm]?[jt]sx?)$/.test(file.path)) continue;
    const comments = commentRanges(file.content, file.path);
    for (const rule of rules) {
      const expression = new RegExp(rule.pattern.source, rule.pattern.flags);
      for (const match of file.content.matchAll(expression)) {
        if (insideComment(match.index, comments)) continue;
        if (findings.length >= 300) return findings;
        const line = file.content.slice(0, match.index).split('\n').length;
        findings.push(
          makeFinding({
            source: 'builtin',
            ruleId: rule.id,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            sourceSeverity: rule.severity,
            description: rule.description,
            remediation: rule.remediation,
            cwe: rule.cwe,
            evidence: [
              sourceEvidence(
                file,
                line,
                `Rule ${rule.id} matched a review-relevant code pattern. Runtime exploitability is unverified.`,
              ),
            ],
          }),
        );
      }
    }
  }
  return findings;
}
