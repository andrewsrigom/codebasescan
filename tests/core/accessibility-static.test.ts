import test from 'node:test';
import assert from 'node:assert/strict';
import { scanAccessibilityStatic } from '../../src/scanners/accessibility-static.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('static accessibility rules find bounded intrinsic JSX candidates', () => {
  const result = scanAccessibilityStatic(
    snapshotFromFiles({
      'src/app/layout.tsx': `export default function Layout({ children }) {
        return <html><body>{children}</body></html>;
      }`,
      'src/form.tsx': `export function Form() {
        return <><img src="/logo.png" /><div onClick={() => save()}>Save</div><input id="email" /><iframe src="/embed" /><a onClick={() => save()}>Action</a></>;
      }`,
    }),
  );
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'TW-A11Y001',
    'TW-A11Y002',
    'TW-A11Y003',
    'TW-A11Y004',
    'TW-A11Y005',
    'TW-A11Y006',
  ]);
  assert.equal(result.runs[0]?.status, 'completed');
});

test('native semantics and complete labels avoid accessibility candidates', () => {
  const result = scanAccessibilityStatic(
    snapshotFromFiles({
      'src/app/layout.tsx': `export default function Layout({ children }) {
        return <html lang="en"><body>{children}</body></html>;
      }`,
      'src/form.tsx': `export function Form() {
        return <><img src="/shape.png" alt="" /><button onClick={() => save()}>Save</button><label htmlFor="email">Email</label><input id="email" /><input type="file" className="hidden" /><select hidden /><iframe src="/embed" title="Preview" /><a href="/next">Next</a></>;
      }`,
    }),
  );
  assert.deepEqual(result.findings, []);
});

test('external Axe JSON is imported without retaining selectors or HTML', () => {
  const result = scanAccessibilityStatic(
    snapshotFromFiles({
      'src/app/page.tsx': `export default function Page() { return <main>Home</main>; }`,
      'codebasescan.axe.json': JSON.stringify({
        url: 'http://127.0.0.1:3000/',
        violations: [
          {
            id: 'color-contrast',
            impact: 'serious',
            help: 'Elements must meet minimum color contrast ratio thresholds',
            description: 'Ensure foreground and background colors meet WCAG thresholds',
            nodes: [{ target: ['.private-selector'], html: '<div>private</div>' }],
          },
        ],
      }),
    }),
  );
  assert.equal(result.runs[1]?.status, 'completed');
  assert.equal(result.findings[0]?.ruleId, 'AXE-COLOR-CONTRAST');
  assert.equal(result.findings[0]?.severity, 'medium');
  assert.ok(!JSON.stringify(result.findings).includes('.private-selector'));
  assert.ok(!JSON.stringify(result.findings).includes('<div>private</div>'));
});

test('invalid Axe JSON fails its capability without affecting static findings', () => {
  const result = scanAccessibilityStatic(
    snapshotFromFiles({
      'src/form.tsx': `export function Form() { return <img src="/logo.png" />; }`,
      'axe-results.json': `{ "violations": null }`,
    }),
  );
  assert.equal(result.runs[1]?.status, 'failed');
  assert.deepEqual(
    result.findings.map((finding) => finding.ruleId),
    ['TW-A11Y001'],
  );
});

test('component names are not downgraded into intrinsic HTML semantics', () => {
  const result = scanAccessibilityStatic(
    snapshotFromFiles({
      'src/form.tsx': `export function Form() {
        return <><Image src="/logo.png" /><Label>Email</Label><Input id="email" /><Select /></>;
      }`,
    }),
  );
  assert.deepEqual(result.findings, []);
});

test('dynamic label references and forwarded intrinsic attributes stay unverified', () => {
  const result = scanAccessibilityStatic(
    snapshotFromFiles({
      'src/form.tsx': `export function Field({ id, ...props }) {
        return <><label htmlFor={id}>Email</label><input id={id} /><textarea {...props} /></>;
      }`,
    }),
  );
  assert.deepEqual(result.findings, []);
});

test('label components with matching htmlFor provide static naming evidence', () => {
  const result = scanAccessibilityStatic(
    snapshotFromFiles({
      'src/form.tsx': `export function Field({ id }) {
        return <><Label htmlFor={id}>Notes</Label><textarea id={id} /></>;
      }`,
    }),
  );
  assert.deepEqual(result.findings, []);
});
