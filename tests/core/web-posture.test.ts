import test from 'node:test';
import assert from 'node:assert/strict';
import { scanWebPosture } from '../../src/scanners/web-posture.ts';
import { snapshotFromFiles } from '../helpers.ts';

test('web posture reports bounded discovery and metadata gaps', () => {
  const result = scanWebPosture(
    snapshotFromFiles({
      'package.json': JSON.stringify({ dependencies: { next: '16.0.0', react: '19.0.0' } }),
      'src/app/page.tsx': `export default function Page() { return <main>Home</main>; }`,
      'src/app/layout.tsx': `export default function Layout({ children }) { return <html lang="en"><body>{children}</body></html>; }`,
      'public/robots.txt': `User-agent: *\nDisallow: /\n`,
      'public/sitemap.xml': `<broken />`,
    }),
  );
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'TW-WEB003',
    'TW-WEB004',
    'TW-WEB005',
  ]);
  assert.equal(result.run.status, 'completed');
});

test('valid static and Next metadata evidence avoids web posture noise', () => {
  const result = scanWebPosture(
    snapshotFromFiles({
      'package.json': JSON.stringify({ dependencies: { next: '16.0.0' } }),
      'src/app/page.tsx': `export default function Page() { return <main>Home</main>; }`,
      'src/app/layout.tsx': `export const metadata = { title: 'Product', description: 'Useful product' }; export default function Layout({ children }) { return <html lang="en"><body>{children}</body></html>; }`,
      'public/robots.txt': `User-agent: *\nAllow: /\n`,
      'public/sitemap.xml': `<?xml version="1.0"?><urlset><url><loc>https://example.test/</loc></url></urlset>`,
      'public/llms.txt': `# Product\n`,
    }),
  );
  assert.deepEqual(result.findings, []);
  assert.match(result.run.detail, /llms\.txt=present/);
});

test('non-web repositories skip web posture without missing-file findings', () => {
  const result = scanWebPosture(
    snapshotFromFiles({ 'package.json': JSON.stringify({ name: 'node-library' }) }),
  );
  assert.deepEqual(result.findings, []);
  assert.equal(result.run.status, 'skipped');
});
