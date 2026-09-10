import ts from 'typescript';
import type { Finding, ScannerRun, Snapshot, SourceFile } from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import { isRuntimeSource } from '../security/paths.ts';

const maximumFindings = 300;
const jsxSource = /\.(?:[cm]?tsx|jsx)$/i;

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function tagName(node: ts.JsxOpeningLikeElement): string {
  return node.tagName.getText(node.getSourceFile());
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
      tagName(ts.isJsxElement(node) ? node.openingElement : node) === 'label'
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
          type === 'hidden' ||
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

export function scanAccessibilityStatic(snapshot: Snapshot): {
  findings: Finding[];
  run: ScannerRun;
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
  const partial = snapshot.truncated || parseFailures > 0 || findings.length >= maximumFindings;
  return {
    findings,
    run: {
      id: 'accessibility-static',
      name: 'Static accessibility review',
      status: files.length ? (partial ? 'partial' : 'completed') : 'skipped',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: findings.length,
      detail: files.length
        ? `Inspected ${files.length} JSX file(s) for four bounded semantic candidates; ${parseFailures} parse failure(s). Runtime focus, contrast, layout, and assistive-technology behavior were not tested.`
        : 'No runtime JSX source was available for static accessibility review.',
      version: '0.2.0',
    },
  };
}
