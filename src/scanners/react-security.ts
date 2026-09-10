import ts from 'typescript';
import type {
  Category,
  Finding,
  ProjectProfile,
  ScannerRun,
  Snapshot,
  SourceFile,
} from '../domain/types.ts';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import { isRuntimeSource } from '../security/paths.ts';

const maximumFindings = 300;
const reactSource = /\.(?:[cm]?tsx|jsx)$/i;
const sensitiveName =
  /(?:api[_-]?key|authorization|cookie|jwt|password|private[_-]?key|refresh[_-]?token|secret|session|token)/i;
const serverOnlyImport =
  /^(?:server-only|next\/headers|next\/server|node:fs(?:\/promises)?|@prisma\/client)$/;
const explicitBrowserInputName =
  /^(?:callbackUrl|continueUrl|destination|next|nextUrl|params|redirect|redirectTo|returnTo|returnUrl|searchParams|targetUrl)$/i;

export interface ReactSecurityResult {
  findings: Finding[];
  run: ScannerRun;
}

function scriptKind(file: string): ts.ScriptKind {
  if (/\.tsx$/i.test(file)) return ts.ScriptKind.TSX;
  return ts.ScriptKind.JSX;
}

function lineOf(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function callName(call: ts.CallExpression): string {
  return call.expression.getText(call.getSourceFile()).replace(/\s+/g, '').slice(0, 180);
}

function hasDirective(source: ts.SourceFile, directive: 'use client' | 'use server'): boolean {
  for (const statement of source.statements) {
    if (!ts.isExpressionStatement(statement) || !ts.isStringLiteral(statement.expression)) break;
    if (statement.expression.text === directive) return true;
  }
  return false;
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  return name.elements.flatMap((element) =>
    ts.isOmittedExpression(element) ? [] : bindingNames(element.name),
  );
}

function isExecutableFunction(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

function containsIdentifier(node: ts.Node | undefined, names: Set<string>): boolean {
  if (!node) return false;
  let found = false;
  const visit = (child: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(child) && names.has(child.text)) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

function functionTaint(node: ts.FunctionLikeDeclaration): Set<string> {
  const tainted = new Set(
    node.parameters
      .flatMap((parameter) => bindingNames(parameter.name))
      .filter((name) => explicitBrowserInputName.test(name)),
  );
  const serverOwnedUrls = new Set<string>();
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    const visit = (child: ts.Node): void => {
      if (child !== node && isExecutableFunction(child)) return;
      if (ts.isVariableDeclaration(child) && child.initializer) {
        const names = bindingNames(child.name);
        if (isServerOwnedUrl(child.initializer, serverOwnedUrls)) {
          for (const name of names) {
            serverOwnedUrls.add(name);
            tainted.delete(name);
          }
          ts.forEachChild(child, visit);
          return;
        }
        const fromInput =
          containsIdentifier(child.initializer, tainted) ||
          /(?:useSearchParams|useParams|URLSearchParams)\s*\(/.test(
            child.initializer.getText(child.getSourceFile()),
          ) ||
          /(?:window\.)?location\.(?:hash|href|search)/.test(
            child.initializer.getText(child.getSourceFile()),
          ) ||
          /\b(?:event|messageEvent)\.(?:currentTarget|target)\.value\b/.test(
            child.initializer.getText(child.getSourceFile()),
          ) ||
          /\b(?:event|messageEvent)\.data\b/.test(
            child.initializer.getText(child.getSourceFile()),
          ) ||
          /(?:localStorage|sessionStorage)\.getItem\s*\(/.test(
            child.initializer.getText(child.getSourceFile()),
          );
        if (fromInput)
          for (const name of names)
            if (!tainted.has(name)) {
              tainted.add(name);
              changed = true;
            }
      }
      ts.forEachChild(child, visit);
    };
    if (node.body) visit(node.body);
    if (!changed) break;
  }
  return tainted;
}

function jsxAttribute(node: ts.JsxAttributes, name: string): ts.JsxAttribute | undefined {
  return node.properties.find(
    (property): property is ts.JsxAttribute =>
      ts.isJsxAttribute(property) && property.name.getText() === name,
  );
}

function attributeExpression(attribute: ts.JsxAttribute | undefined): ts.Expression | undefined {
  if (!attribute?.initializer || !ts.isJsxExpression(attribute.initializer)) return undefined;
  return attribute.initializer.expression;
}

function attributeText(attribute: ts.JsxAttribute | undefined): string | undefined {
  if (!attribute?.initializer || !ts.isStringLiteral(attribute.initializer)) return undefined;
  return attribute.initializer.text;
}

function isStaticOrSanitizedHtml(expression: ts.Expression | undefined): boolean {
  if (!expression || ts.isStringLiteralLike(expression)) return true;
  const text = expression.getText(expression.getSourceFile()).replace(/\s+/g, ' ');
  return (
    /(?:DOMPurify\.)?sanitize\s*\(|escapeHtml\s*\(|sanitizeHtml\s*\(/.test(text) ||
    (/JSON\.stringify\s*\(/.test(text) && /\.replace(?:All)?\s*\(\s*\/</.test(text))
  );
}

function dangerousHtmlExpression(attribute: ts.JsxAttribute): ts.Expression | undefined {
  const expression = attributeExpression(attribute);
  if (!expression || !ts.isObjectLiteralExpression(expression)) return expression;
  const property = expression.properties.find(
    (item): item is ts.PropertyAssignment =>
      ts.isPropertyAssignment(item) && item.name.getText(expression.getSourceFile()) === '__html',
  );
  return property?.initializer;
}

function isServerOwnedUrl(expression: ts.Expression, trustedNames = new Set<string>()): boolean {
  if (ts.isIdentifier(expression) && trustedNames.has(expression.text)) return true;
  if (ts.isStringLiteralLike(expression)) return true;
  if (ts.isNoSubstitutionTemplateLiteral(expression)) return true;
  if (ts.isTemplateExpression(expression))
    return (
      /^(?:\/|#|\?)/.test(expression.head.text) ||
      /^(?:mailto|tel):/i.test(expression.head.text) ||
      /^https?:\/\/[^/]+(?:\/|$)/i.test(expression.head.text)
    );
  if (ts.isConditionalExpression(expression))
    return (
      isServerOwnedUrl(expression.whenTrue, trustedNames) &&
      isServerOwnedUrl(expression.whenFalse, trustedNames)
    );
  if (ts.isCallExpression(expression)) {
    const callee = callName(expression).split('.').at(-1) ?? '';
    if (
      /^(?:build|create|localize|resolve|sanitize|safe)[A-Za-z0-9]*(?:Href|Path|Paths|Url)$/i.test(
        callee,
      )
    )
      return true;
    if (
      /^(?:setPathQueryParam|preserve[A-Za-z0-9]*Context)$/i.test(callee) &&
      expression.arguments[0] &&
      isServerOwnedUrl(expression.arguments[0], trustedNames)
    )
      return true;
  }
  if (ts.isNewExpression(expression) && expression.expression.getText() === 'URL') {
    const destination = expression.arguments?.[0];
    return Boolean(destination && isServerOwnedUrl(destination, trustedNames));
  }
  return false;
}

function isSensitiveUrlAttribute(tag: string, attribute: 'href' | 'src'): boolean {
  const component = tag.split('.').at(-1)?.toLowerCase();
  if (attribute === 'href') return component === 'a' || component === 'link';
  return component === 'iframe' || component === 'script';
}

function isNavigationCall(callee: string): boolean {
  return (
    /^(?:router|navigation|history)\.(?:push|replace)$/.test(callee) ||
    /^(?:(?:window\.)?location)\.(?:assign|replace)$/.test(callee) ||
    /^(?:window\.)?open$/.test(callee)
  );
}

function inlineMessageHandler(call: ts.CallExpression): ts.FunctionLikeDeclaration | undefined {
  const event = call.arguments[0];
  const handler = call.arguments[1];
  if (!event || !ts.isStringLiteralLike(event) || event.text !== 'message' || !handler) return;
  return ts.isArrowFunction(handler) || ts.isFunctionExpression(handler) ? handler : undefined;
}

function componentName(node: ts.FunctionLikeDeclaration): string | undefined {
  if (ts.isFunctionDeclaration(node)) return node.name?.text;
  if (
    (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
    ts.isVariableDeclaration(node.parent) &&
    ts.isIdentifier(node.parent.name)
  )
    return node.parent.name.text;
  return undefined;
}

function isAsync(node: ts.FunctionLikeDeclaration): boolean {
  return Boolean(node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword));
}

function reactFinding(input: {
  file: SourceFile;
  source: ts.SourceFile;
  node: ts.Node;
  ruleId: string;
  title: string;
  category: Category;
  severity: 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
  cwe: string[];
  observation: string;
}): Finding {
  const evidence = sourceEvidence(input.file, lineOf(input.source, input.node), input.observation);
  evidence.kind = 'inferred';
  return makeFinding({
    source: 'react',
    ruleId: input.ruleId,
    title: input.title,
    category: input.category,
    severity: input.severity,
    sourceSeverity: input.severity.toUpperCase(),
    description: input.description,
    remediation: input.remediation,
    cwe: input.cwe,
    evidence: [evidence],
  });
}

function clientFileFindings(file: SourceFile, source: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const add = (finding: Finding): void => {
    if (findings.length < maximumFindings) findings.push(finding);
  };

  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier))
      continue;
    if (!serverOnlyImport.test(statement.moduleSpecifier.text)) continue;
    add(
      reactFinding({
        file,
        source,
        node: statement,
        ruleId: 'TW-REACT008',
        title: 'Client module imports a server-only boundary',
        category: 'secrets',
        severity: 'high',
        description:
          'A module marked use client imports an API intended for server execution. The build may reject it, tree-shake it, or expose an unintended server/client boundary.',
        remediation:
          'Move the server operation into a Server Component, Route Handler, or Server Action and pass only minimal serializable non-sensitive data to the client.',
        cwe: ['CWE-200'],
        observation: `Client module imports ${statement.moduleSpecifier.text}.`,
      }),
    );
  }

  const visit = (node: ts.Node, tainted = new Set<string>()): void => {
    if (isExecutableFunction(node)) {
      const name = componentName(node);
      if (name && /^[A-Z]/.test(name) && isAsync(node))
        add(
          reactFinding({
            file,
            source,
            node,
            ruleId: 'TW-REACT009',
            title: 'Client Component is declared async',
            category: 'code',
            severity: 'medium',
            description:
              'React Client Components cannot be async functions. Data fetching or privileged work may be crossing the server/client boundary incorrectly.',
            remediation:
              'Fetch in a Server Component and pass serializable data, or perform client-side fetching inside an effect or supported data library.',
            cwe: ['CWE-710'],
            observation: `Client Component ${name} is async.`,
          }),
        );
      const nextTaint = functionTaint(node);
      if (node.body) ts.forEachChild(node.body, (child) => visit(child, nextTaint));
      return;
    }

    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      const attributes = node.attributes;
      const html = jsxAttribute(attributes, 'dangerouslySetInnerHTML');
      if (html) {
        const value = dangerousHtmlExpression(html);
        if (!isStaticOrSanitizedHtml(value))
          add(
            reactFinding({
              file,
              source,
              node: html,
              ruleId: 'TW-REACT001',
              title: 'Dynamic HTML reaches a React rendering bypass',
              category: 'injection',
              severity: 'high',
              description:
                'A dynamic expression reaches dangerouslySetInnerHTML without a recognized sanitizer. Static analysis does not prove attacker control, but React escaping is bypassed.',
              remediation:
                'Render structured React nodes or sanitize with a maintained allowlist-based HTML sanitizer immediately before the sink. Add script, event-handler, URL, SVG, and mutation-XSS tests.',
              cwe: ['CWE-79'],
              observation:
                'Dynamic HTML reaches dangerouslySetInnerHTML without recognized sanitization.',
            }),
          );
      }

      const tag = node.tagName.getText(source);
      const href = jsxAttribute(attributes, 'href');
      const src = jsxAttribute(attributes, 'src');
      for (const [attribute, label] of [
        [href, 'href'],
        [src, 'src'],
      ] as const) {
        const value = attributeExpression(attribute);
        if (
          attribute &&
          value &&
          isSensitiveUrlAttribute(tag, label) &&
          containsIdentifier(value, tainted) &&
          !isServerOwnedUrl(value)
        )
          add(
            reactFinding({
              file,
              source,
              node: attribute,
              ruleId: 'TW-REACT002',
              title: 'Client-controlled URL reaches a navigation or resource sink',
              category: 'configuration',
              severity: 'medium',
              description:
                'A value derived from component input or browser URL state reaches a JSX URL attribute without a recognized server-owned prefix.',
              remediation:
                'Use route identifiers or enforce allowed protocols, origins, and paths before navigation or resource loading. Reject javascript:, data:, scheme-relative, and unexpected external destinations.',
              cwe: ['CWE-79', 'CWE-601'],
              observation: `${tag}.${label} receives a client-controlled value.`,
            }),
          );
      }

      const target = attributeText(jsxAttribute(attributes, 'target'));
      if (target === '_blank') {
        const rel = attributeText(jsxAttribute(attributes, 'rel')) ?? '';
        if (!/\bnoreferrer\b/i.test(rel))
          add(
            reactFinding({
              file,
              source,
              node,
              ruleId: 'TW-REACT006',
              title: 'New-tab link lacks explicit referrer protection',
              category: 'configuration',
              severity: 'low',
              description:
                'A target=_blank link does not declare noreferrer. Referrer disclosure may remain; noreferrer also provides opener isolation in modern browsers.',
              remediation: 'Add rel="noopener noreferrer" to external new-tab links.',
              cwe: ['CWE-1022', 'CWE-200'],
              observation: `${tag} opens a new tab without complete rel protection.`,
            }),
          );
      }
    }

    if (ts.isCallExpression(node)) {
      const callee = callName(node);
      const first = node.arguments[0];
      if (
        isNavigationCall(callee) &&
        first &&
        containsIdentifier(first, tainted) &&
        !isServerOwnedUrl(first)
      )
        add(
          reactFinding({
            file,
            source,
            node,
            ruleId: 'TW-REACT002',
            title: 'Client-controlled URL reaches a navigation or resource sink',
            category: 'configuration',
            severity: 'medium',
            description:
              'A value derived from component input or browser URL state reaches a client navigation API without a recognized server-owned prefix.',
            remediation:
              'Map user choices to server-owned routes or enforce allowed protocols, origins, and paths before navigation.',
            cwe: ['CWE-601'],
            observation: `${callee} receives a client-controlled destination.`,
          }),
        );

      if (/(?:localStorage|sessionStorage)\.(?:getItem|setItem)$/.test(callee)) {
        const key = first && ts.isStringLiteralLike(first) ? first.text : '';
        if (sensitiveName.test(key))
          add(
            reactFinding({
              file,
              source,
              node,
              ruleId: 'TW-REACT003',
              title: 'Authentication-shaped data uses browser storage',
              category: 'secrets',
              severity: 'medium',
              description:
                'A token-, session-, or credential-shaped key is read from or written to Web Storage, where injected scripts can access it.',
              remediation:
                'Prefer an HttpOnly Secure cookie with an explicit SameSite policy. If browser storage is unavoidable, minimize privilege and lifetime and harden against script injection.',
              cwe: ['CWE-922'],
              observation: `${callee} accesses the sensitive-looking key ${key}.`,
            }),
          );
      }

      if (/(?:^|\.)postMessage$/.test(callee)) {
        const target = node.arguments[1];
        const wildcard = target && ts.isStringLiteralLike(target) && target.text === '*';
        const options = target && ts.isObjectLiteralExpression(target) ? target : undefined;
        const wildcardOption = options?.properties.some(
          (property) =>
            ts.isPropertyAssignment(property) &&
            property.name.getText(source) === 'targetOrigin' &&
            ts.isStringLiteralLike(property.initializer) &&
            property.initializer.text === '*',
        );
        if (wildcard || wildcardOption)
          add(
            reactFinding({
              file,
              source,
              node,
              ruleId: 'TW-REACT004',
              title: 'postMessage sends data to a wildcard origin',
              category: 'configuration',
              severity: 'medium',
              description:
                'A browser message is sent with targetOrigin="*", allowing any current receiver origin to accept it.',
              remediation:
                'Use an exact trusted origin and validate the receiver lifecycle. Never send secrets through a wildcard target.',
              cwe: ['CWE-346'],
              observation: `${callee} uses a wildcard target origin.`,
            }),
          );
      }

      if (/(?:^|\.)addEventListener$/.test(callee)) {
        const handler = inlineMessageHandler(node);
        if (handler?.body && !/\.origin\b/.test(handler.body.getText(source)))
          add(
            reactFinding({
              file,
              source,
              node,
              ruleId: 'TW-REACT005',
              title: 'Message handler has no visible origin check',
              category: 'authorization',
              severity: 'medium',
              description:
                'An inline message-event handler processes cross-document messages without visibly checking event.origin.',
              remediation:
                'Compare event.origin to an exact allowlist before parsing or acting on event.data, and validate the message schema.',
              cwe: ['CWE-346'],
              observation: 'Inline message handler has no visible event.origin validation.',
            }),
          );
      }
    }

    ts.forEachChild(node, (child) => visit(child, tainted));
  };
  visit(source);
  return findings;
}

function sensitiveServerProps(
  snapshot: Snapshot,
  profile: ProjectProfile,
  clientFiles: Set<string>,
): Finding[] {
  const findings: Finding[] = [];
  const files = new Map(snapshot.files.map((file) => [file.path, file]));
  for (const item of profile.imports) {
    if (!item.resolvedFile || !clientFiles.has(item.resolvedFile)) continue;
    if (clientFiles.has(item.file)) continue;
    const file = files.get(item.file);
    if (!file || !reactSource.test(file.path)) continue;
    const source = ts.createSourceFile(
      file.path,
      file.content,
      ts.ScriptTarget.Latest,
      true,
      scriptKind(file.path),
    );
    const clientBindings = new Set(item.bindings.map((binding) => binding.local));
    const visit = (node: ts.Node): void => {
      if (findings.length >= maximumFindings) return;
      if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
        const component = node.tagName.getText(source).split('.')[0] ?? '';
        if (clientBindings.has(component))
          for (const property of node.attributes.properties) {
            if (!ts.isJsxAttribute(property) || !sensitiveName.test(property.name.getText(source)))
              continue;
            findings.push(
              reactFinding({
                file,
                source,
                node: property,
                ruleId: 'TW-REACT007',
                title: 'Sensitive-shaped data crosses into a Client Component',
                category: 'secrets',
                severity: 'high',
                description:
                  'A Server Component passes a token-, secret-, cookie-, password-, or session-shaped prop into an imported Client Component. Serialized props are visible to the browser.',
                remediation:
                  'Keep credentials and privileged session objects on the server. Pass only the minimal non-sensitive fields required for rendering.',
                cwe: ['CWE-200'],
                observation: `${component}.${property.name.getText(source)} crosses the server/client boundary.`,
              }),
            );
          }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return findings;
}

export function scanReactSecurity(
  snapshot: Snapshot,
  profile: ProjectProfile,
): ReactSecurityResult {
  const started = performance.now();
  const parsed = snapshot.files
    .filter((file) => isRuntimeSource(file) && reactSource.test(file.path))
    .map((file) => ({
      file,
      source: ts.createSourceFile(
        file.path,
        file.content,
        ts.ScriptTarget.Latest,
        true,
        scriptKind(file.path),
      ),
    }));
  if (!parsed.length)
    return {
      findings: [],
      run: {
        id: 'react-security',
        name: 'React client security',
        status: 'skipped',
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        findings: 0,
        detail: 'No runtime JSX or TSX source was available. No clean React result is implied.',
        version: '0.4.0',
      },
    };

  const clientFiles = new Set(
    parsed.filter(({ source }) => hasDirective(source, 'use client')).map(({ file }) => file.path),
  );
  const findings = parsed
    .filter(({ file }) => clientFiles.has(file.path))
    .flatMap(({ file, source }) => clientFileFindings(file, source));
  findings.push(...sensitiveServerProps(snapshot, profile, clientFiles));
  const limited = findings.slice(0, maximumFindings);
  const partial = snapshot.truncated || findings.length > maximumFindings;
  return {
    findings: limited,
    run: {
      id: 'react-security',
      name: 'React client security',
      status: partial ? 'partial' : 'completed',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: limited.length,
      detail: `Analyzed ${parsed.length} runtime JSX/TSX file(s), including ${clientFiles.size} explicit Client Component module(s), for rendering, navigation, browser storage, messaging, new-tab, and server/client boundary risks.${partial ? ' Coverage was bounded.' : ''}`,
      version: '0.4.0',
    },
  };
}
