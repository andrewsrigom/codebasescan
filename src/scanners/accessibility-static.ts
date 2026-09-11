import ts from 'typescript';
import type { Finding, ScannerRun, Snapshot, SourceFile } from '../domain/types.ts';
import { digest, makeFinding, sourceEvidence } from '../domain/findings.ts';
import { isRuntimeSource } from '../security/paths.ts';
import { redact } from '../security/redact.ts';

const maximumFindings = 300;
const jsxSource = /\.(?:[cm]?tsx|jsx)$/i;

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function tagName(node: ts.JsxOpeningLikeElement): string {
  return node.tagName.getText(node.getSourceFile());
}

function isLabelTag(name: string): boolean {
  return name === 'label' || name === 'Label' || name.endsWith('.Label');
}

function attribute(node: ts.JsxOpeningLikeElement, name: string): ts.JsxAttribute | undefined {
  return node.attributes.properties.find(
    (item): item is ts.JsxAttribute =>
      ts.isJsxAttribute(item) && item.name.getText(node.getSourceFile()).toLowerCase() === name,
  );
}

function literalAttribute(node: ts.JsxOpeningLikeElement, name: string): string | undefined {
  const found = attribute(node, name);
  return found?.initializer && ts.isStringLiteral(found.initializer)
    ? found.initializer.text
    : undefined;
}

function attributeReference(node: ts.JsxOpeningLikeElement, name: string): string | undefined {
  const found = attribute(node, name);
  if (!found?.initializer) return undefined;
  if (ts.isStringLiteral(found.initializer)) return `literal:${found.initializer.text}`;
  if (ts.isJsxExpression(found.initializer) && found.initializer.expression)
    return `expression:${found.initializer.expression.getText(node.getSourceFile())}`;
  return undefined;
}

function hasSpreadAttributes(node: ts.JsxOpeningLikeElement): boolean {
  return node.attributes.properties.some(ts.isJsxSpreadAttribute);
}

function isStaticallyHiddenControl(
  node: ts.JsxOpeningLikeElement,
  type: string | undefined,
): boolean {
  if (type === 'hidden' || attribute(node, 'hidden')) return true;
  return literalAttribute(node, 'classname')?.trim() === 'hidden';
}

function finding(
  file: SourceFile,
  source: ts.SourceFile,
  node: ts.Node,
  ruleId: string,
  title: string,
  description: string,
  remediation: string,
  observation: string,
): Finding {
  const evidence = sourceEvidence(file, lineOf(source, node), observation);
  evidence.kind = 'inferred';
  return makeFinding({
    source: 'accessibility',
    ruleId,
    title,
    category: 'accessibility',
    severity: 'low',
    sourceSeverity: 'review',
    description,
    remediation,
    cwe: [],
    evidence: [evidence],
  });
}

function insideLabel(node: ts.Node): boolean {
  let parent = node.parent;
  while (parent) {
    if (ts.isJsxElement(parent) && tagName(parent.openingElement) === 'label') return true;
    parent = parent.parent;
  }
  return false;
}

function scanFile(file: SourceFile): { findings: Finding[]; parseFailed: boolean } {
  const source = ts.createSourceFile(
    file.path,
    file.content,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] })
    .parseDiagnostics;
  if (diagnostics?.length) return { findings: [], parseFailed: true };
  const findings: Finding[] = [];
  const labels = new Set<string>();
  const collectLabels = (node: ts.Node): void => {
    if (
      (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) &&
      isLabelTag(tagName(ts.isJsxElement(node) ? node.openingElement : node))
    ) {
      const opening = ts.isJsxElement(node) ? node.openingElement : node;
      const target = attributeReference(opening, 'htmlfor');
      if (target) labels.add(target);
    }
    ts.forEachChild(node, collectLabels);
  };
  collectLabels(source);
  const visit = (node: ts.Node): void => {
    if (findings.length >= maximumFindings) return;
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
      const opening = ts.isJsxElement(node) ? node.openingElement : node;
      const tag = tagName(opening);
      if (tag === 'img' && !attribute(opening, 'alt'))
        findings.push(
          finding(
            file,
            source,
            opening,
            'TW-A11Y001',
            'Image has no alternative-text declaration',
            'An intrinsic image has no alt attribute. Static analysis cannot determine the image purpose.',
            'Add meaningful alt text, or alt="" when the image is intentionally decorative.',
            'Intrinsic img element has no alt attribute.',
          ),
        );
      if (tag === 'iframe' && !attribute(opening, 'title') && !hasSpreadAttributes(opening))
        findings.push(
          finding(
            file,
            source,
            opening,
            'TW-A11Y005',
            'Inline frame has no static accessible name',
            'An intrinsic iframe has no title attribute, so its purpose may not be announced clearly.',
            'Add a concise title describing the embedded content or forward a verified title prop.',
            'Intrinsic iframe has no title attribute.',
          ),
        );
      if (
        tag === 'a' &&
        attribute(opening, 'onclick') &&
        !attribute(opening, 'href') &&
        !hasSpreadAttributes(opening)
      )
        findings.push(
          finding(
            file,
            source,
            opening,
            'TW-A11Y006',
            'Anchor click handler has no navigation target',
            'An intrinsic anchor has a click handler but no href, so native keyboard and link behavior are not established.',
            'Use a button for an action or provide a real href when the element navigates.',
            'Clickable intrinsic anchor has no href attribute.',
          ),
        );
      if (
        (tag === 'div' || tag === 'span') &&
        attribute(opening, 'onclick') &&
        (!attribute(opening, 'onkeydown') ||
          !attribute(opening, 'role') ||
          !attribute(opening, 'tabindex'))
      )
        findings.push(
          finding(
            file,
            source,
            opening,
            'TW-A11Y002',
            'Pointer-only custom interactive element',
            'A div or span has a click handler without the complete keyboard, role, and focus declarations expected for a custom control.',
            'Prefer a native button or link. Otherwise provide an appropriate role, focusability, and keyboard behavior.',
            'Custom clickable element lacks role, tabIndex, or keyboard handling.',
          ),
        );
      if (
        tag === 'html' &&
        /(?:^|\/)app\/(?:[^/]+\/)*layout\.[cm]?tsx?$/.test(file.path) &&
        !attribute(opening, 'lang')
      )
        findings.push(
          finding(
            file,
            source,
            opening,
            'TW-A11Y003',
            'Root document language is not declared',
            'A Next.js root layout renders html without a lang attribute.',
            'Set the document language to the primary locale and update it when locale routing changes.',
            'Root layout html element has no lang attribute.',
          ),
        );
      if (['input', 'select', 'textarea'].includes(tag)) {
        const type = literalAttribute(opening, 'type')?.toLowerCase();
        const id = attributeReference(opening, 'id');
        const named =
          isStaticallyHiddenControl(opening, type) ||
          Boolean(attribute(opening, 'aria-label')) ||
          Boolean(attribute(opening, 'aria-labelledby')) ||
          Boolean(id && labels.has(id)) ||
          insideLabel(opening) ||
          hasSpreadAttributes(opening);
        if (!named)
          findings.push(
            finding(
              file,
              source,
              opening,
              'TW-A11Y004',
              'Form control has no static accessible-name evidence',
              'An intrinsic form control is not linked to a label and has no static ARIA naming attribute.',
              'Associate a visible label with htmlFor/id or provide an appropriate accessible name.',
              'Form control lacks a linked label or ARIA name in the captured JSX.',
            ),
          );
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { findings, parseFailed: false };
}

function axeText(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const normalized = value
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .trim()
    .slice(0, 500);
  return normalized ? redact(normalized) : fallback;
}

function axeSeverity(value: unknown): Finding['severity'] {
  if (value === 'critical') return 'high';
  if (value === 'serious') return 'medium';
  if (value === 'moderate') return 'low';
  return 'info';
}

function importAxeResults(snapshot: Snapshot): { findings: Finding[]; run: ScannerRun } {
  const started = performance.now();
  const file = snapshot.files.find(
    (candidate) =>
      isRuntimeSource(candidate) &&
      ['codebasescan.axe.json', 'axe-results.json', 'axe-report.json'].includes(
        candidate.path.toLowerCase(),
      ),
  );
  if (!file)
    return {
      findings: [],
      run: {
        id: 'axe-results',
        name: 'Imported Axe runtime accessibility',
        status: 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail:
          'No root codebasescan.axe.json, axe-results.json, or axe-report.json artifact was captured. CodebaseScan did not execute the target application or a browser.',
        version: '0.1.0',
      },
    };
  try {
    const parsed: unknown = JSON.parse(file.content);
    const documents = Array.isArray(parsed) ? parsed.slice(0, 20) : [parsed];
    const findings: Finding[] = [];
    let violations = 0;
    for (const document of documents) {
      if (!document || typeof document !== 'object' || Array.isArray(document))
        throw new Error('invalid document');
      const rawViolations = (document as Record<string, unknown>).violations;
      if (!Array.isArray(rawViolations)) throw new Error('missing violations');
      for (const value of rawViolations.slice(0, maximumFindings - findings.length)) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
        const violation = value as Record<string, unknown>;
        if (typeof violation.id !== 'string' || !/^[a-z0-9-]{1,100}$/i.test(violation.id)) continue;
        const nodes = Array.isArray(violation.nodes) ? Math.min(violation.nodes.length, 10_000) : 0;
        const observation = `Imported Axe rule ${violation.id} reported ${nodes} affected node(s); selectors and HTML were not retained.`;
        const evidence = {
          id: digest(`${file.path}:${violation.id}:${observation}`).slice(0, 16),
          kind: 'observed' as const,
          scope: file.scope,
          file: file.path,
          startLine: 1,
          endLine: 1,
          focusLine: 1,
          excerpt: `Axe ${violation.id}: ${nodes} affected node(s).`,
          fileDigest: file.digest,
          observation,
        };
        findings.push(
          makeFinding({
            source: 'axe',
            ruleId: `AXE-${violation.id.toUpperCase()}`,
            title: axeText(violation.help, `Axe reported ${violation.id}`),
            category: 'accessibility',
            severity: axeSeverity(violation.impact),
            sourceSeverity:
              typeof violation.impact === 'string' ? violation.impact.slice(0, 40) : 'unknown',
            description: `${axeText(violation.description, 'Axe reported a runtime accessibility issue.')} The imported artifact groups ${nodes} affected node(s).`,
            remediation:
              'Review the Axe rule in the tested page, correct the affected markup, and rerun the external accessibility test.',
            cwe: [],
            evidence: [evidence],
          }),
        );
        violations++;
      }
    }
    const partial = findings.length >= maximumFindings || documents.length >= 20;
    return {
      findings,
      run: {
        id: 'axe-results',
        name: 'Imported Axe runtime accessibility',
        status: partial ? 'partial' : 'completed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: findings.length,
        detail: `Imported ${violations} bounded Axe violation group(s) from ${file.path}. Selectors, HTML fragments, and browser execution were not retained or performed.`,
        version: '0.1.0',
      },
    };
  } catch {
    return {
      findings: [],
      run: {
        id: 'axe-results',
        name: 'Imported Axe runtime accessibility',
        status: 'failed',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: `${file.path} is not a bounded Axe JSON result artifact.`,
        version: '0.1.0',
      },
    };
  }
}

export function scanAccessibilityStatic(snapshot: Snapshot): {
  findings: Finding[];
  runs: ScannerRun[];
} {
  const started = performance.now();
  const files = snapshot.files.filter((file) => isRuntimeSource(file) && jsxSource.test(file.path));
  const findings: Finding[] = [];
  let parseFailures = 0;
  for (const file of files) {
    const result = scanFile(file);
    parseFailures += Number(result.parseFailed);
    findings.push(...result.findings.slice(0, maximumFindings - findings.length));
    if (findings.length >= maximumFindings) break;
  }
  const imported = importAxeResults(snapshot);
  const partial = snapshot.truncated || parseFailures > 0 || findings.length >= maximumFindings;
  return {
    findings: [...findings, ...imported.findings],
    runs: [
      {
        id: 'accessibility-static',
        name: 'Static accessibility review',
        status: files.length ? (partial ? 'partial' : 'completed') : 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: findings.length,
        detail: files.length
          ? `Inspected ${files.length} JSX file(s) for six bounded semantic candidates; ${parseFailures} parse failure(s). Runtime focus, contrast, layout, and assistive-technology behavior require imported external evidence.`
          : 'No runtime JSX source was available for static accessibility review.',
        version: '0.5.0',
      },
      imported.run,
    ],
  };
}
