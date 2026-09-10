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
        return <><img src="/logo.png" /><div onClick={() => save()}>Save</div><input id="email" /></>;
      }`,
    }),
  );
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'TW-A11Y001',
    'TW-A11Y002',
    'TW-A11Y003',
    'TW-A11Y004',
  ]);
  assert.equal(result.run.status, 'completed');
});

test('native semantics and complete labels avoid accessibility candidates', () => {
  const result = scanAccessibilityStatic(
    snapshotFromFiles({
      'src/app/layout.tsx': `export default function Layout({ children }) {
        return <html lang="en"><body>{children}</body></html>;
      }`,
      'src/form.tsx': `export function Form() {
        return <><img src="/shape.png" alt="" /><button onClick={() => save()}>Save</button><label htmlFor="email">Email</label><input id="email" /></>;
      }`,
    }),
  );
  assert.deepEqual(result.findings, []);
});
