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
  assert.match(result.run.detail, /llms\.txt=1/);
});

test('web posture associates discovery files with each monorepo app root', () => {
  const result = scanWebPosture(
    snapshotFromFiles({
      'package.json': JSON.stringify({ private: true }),
      'apps/marketing/src/app/page.tsx': `export default function Page() { return <main>Home</main>; }`,
      'apps/marketing/src/app/app/page.tsx': `export default function AppPage() { return <main>Product</main>; }`,
      'apps/marketing/src/app/layout.tsx': `export async function generateMetadata() { return { title: 'Product' }; } export default function Layout({ children }) { return <html lang="en"><body>{children}</body></html>; }`,
      'apps/marketing/src/app/robots.ts': `export default function robots() { return { rules: { userAgent: '*', allow: '/' } }; }`,
      'apps/marketing/public/sitemap.xml': `<urlset><url><loc>https://example.test/</loc></url></urlset>`,
      'apps/dashboard/src/app/page.tsx': `export default function Page() { return <main>Dashboard</main>; }`,
    }),
  );
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'TW-WEB001',
    'TW-WEB002',
  ]);
  assert.match(result.run.detail, /2 web app root/);
});

test('Next.js root route groups count as one web app, not as nested apps', () => {
  const result = scanWebPosture(
    snapshotFromFiles({
      'package.json': JSON.stringify({ dependencies: { next: '16.0.0' } }),
      'src/app/(main)/page.tsx': `export default function Page() { return <main>Home</main>; }`,
      'src/app/(main)/layout.tsx': `export const metadata = { title: 'App' }; export default function Layout({ children }) { return <html lang="en"><body>{children}</body></html>; }`,
      'src/app/(main)/settings/page.tsx': `export default function Settings() { return <main>Settings</main>; }`,
    }),
  );
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'TW-WEB001',
    'TW-WEB002',
  ]);
  assert.match(result.run.detail, /1 web app root/);
});

test('non-web repositories skip web posture without missing-file findings', () => {
  const result = scanWebPosture(
    snapshotFromFiles({ 'package.json': JSON.stringify({ name: 'node-library' }) }),
  );
  assert.deepEqual(result.findings, []);
  assert.equal(result.run.status, 'skipped');
});

test('desktop webviews are excluded while ordinary React web apps remain applicable', () => {
  const result = scanWebPosture(
    snapshotFromFiles({
      'package.json': JSON.stringify({ private: true }),
      'apps/desktop/wails.json': JSON.stringify({ name: 'DesktopApp' }),
      'apps/desktop/frontend/package.json': JSON.stringify({
        dependencies: { react: '19.0.0' },
      }),
      'apps/desktop/frontend/src/App.tsx': `export function App() { return <main>Desktop</main>; }`,
      'apps/site/package.json': JSON.stringify({ dependencies: { react: '19.0.0' } }),
      'apps/site/src/App.tsx': `export function App() { return <main>Website</main>; }`,
    }),
  );
  assert.deepEqual(
    result.findings.map((finding) => finding.evidence[0]?.file),
    ['apps/site/src/App.tsx', 'apps/site/src/App.tsx'],
  );
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'TW-WEB001',
    'TW-WEB002',
  ]);
});

test('desktop-only React webviews make Web Presence not applicable', () => {
  const result = scanWebPosture(
    snapshotFromFiles({
      'apps/desktop/wails.json': JSON.stringify({ name: 'DesktopApp' }),
      'apps/desktop/frontend/package.json': JSON.stringify({
        dependencies: { react: '19.0.0' },
      }),
      'apps/desktop/frontend/src/App.tsx': `export function App() { return <main>Desktop</main>; }`,
    }),
  );
  assert.deepEqual(result.findings, []);
  assert.equal(result.run.status, 'skipped');
  assert.match(result.run.detail, /desktop-container/);
});
