import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanReactSecurity } from '../../src/scanners/react-security.ts';
import { snapshotFromFiles, snapshotOf } from '../helpers.ts';

function scan(content: string) {
  const snapshot = snapshotOf(content, 'src/components/example.tsx');
  return scanReactSecurity(snapshot, profileProject(snapshot).profile);
}

test('React HTML rule distinguishes dynamic input from recognized sanitization', () => {
  const vulnerable = scan(`
    'use client';
    export function Preview({ html }) {
      return <article dangerouslySetInnerHTML={{ __html: html }} />;
    }
  `);
  assert.ok(vulnerable.findings.some((finding) => finding.ruleId === 'TW-REACT001'));

  const safe = scan(`
    'use client';
    export function Preview({ html }) {
      return <article dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
    }
  `);
  assert.ok(!safe.findings.some((finding) => finding.ruleId === 'TW-REACT001'));
});

test('React client rules cover URLs, browser storage, messaging, and new tabs', () => {
  const result = scan(`
    'use client';
    export function AccountLink({ destination, token }) {
      localStorage.setItem('access_token', token);
      window.parent.postMessage({ token }, '*');
      window.addEventListener('message', (event) => consume(event.data));
      return <a href={destination} target="_blank">Continue</a>;
    }
  `);
  const ids = new Set(result.findings.map((finding) => finding.ruleId));
  assert.ok(ids.has('TW-REACT002'));
  assert.ok(ids.has('TW-REACT003'));
  assert.ok(ids.has('TW-REACT004'));
  assert.ok(ids.has('TW-REACT005'));
  assert.ok(ids.has('TW-REACT006'));
});

test('React client boundary rules catch server imports and async components', () => {
  const result = scan(`
    'use client';
    import { cookies } from 'next/headers';
    export async function Dashboard() {
      return <div>{String(cookies)}</div>;
    }
  `);
  const ids = new Set(result.findings.map((finding) => finding.ruleId));
  assert.ok(ids.has('TW-REACT008'));
  assert.ok(ids.has('TW-REACT009'));
});

test('Server Components do not pass sensitive-shaped props to Client Components', () => {
  const snapshot = snapshotFromFiles({
    'src/app/page.tsx': `
      import { ClientPanel } from '../components/client-panel';
      export default async function Page() {
        const session = await getSession();
        return <ClientPanel session={session} />;
      }
    `,
    'src/components/client-panel.tsx': `
      'use client';
      export function ClientPanel({ session }) { return <div>{session.user.name}</div>; }
    `,
  });
  const result = scanReactSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-REACT007'));
});

test('typed credential metadata may cross the server-client boundary', () => {
  const snapshot = snapshotFromFiles({
    'src/app/page.tsx': `
      import { ClientPanel } from '../components/client-panel';
      export default function Page() {
        const sessions = readSessions();
        const apiKeys = readApiKeys();
        return <ClientPanel sessions={sessions} apiKeys={apiKeys} />;
      }
    `,
    'src/components/client-panel.tsx': `
      'use client';
      import type { SessionMetadata, ApiKeyMetadata } from '../records';
      type ClientPanelProps = {
        sessions: SessionMetadata[];
        apiKeys: ApiKeyMetadata[];
      };
      export function ClientPanel({ sessions, apiKeys }: ClientPanelProps) {
        return <div>{sessions.length + apiKeys.length}</div>;
      }
    `,
    'src/records.ts': `
      type BaseSessionMetadata = { id: string; expiresAt: string; };
      export type SessionMetadata = BaseSessionMetadata & { active: boolean; };
      export type ApiKeyStatus = 'active' | 'revoked';
      export type ApiKeyMetadata = {
        id: string;
        prefix: string;
        status: ApiKeyStatus;
      };
    `,
  });
  const result = scanReactSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-REACT007'));
});

test('typed secret-bearing records still trigger the client-boundary candidate', () => {
  const snapshot = snapshotFromFiles({
    'src/app/page.tsx': `
      import { ClientPanel } from '../components/client-panel';
      export default function Page() {
        return <ClientPanel sessions={readSessions()} />;
      }
    `,
    'src/components/client-panel.tsx': `
      'use client';
      import type { SessionRecord } from '../records';
      type ClientPanelProps = { sessions: SessionRecord[]; };
      export function ClientPanel({ sessions }: ClientPanelProps) {
        return <div>{sessions.length}</div>;
      }
    `,
    'src/records.ts': `
      export type SessionRecord = { id: string; sessionToken: string; };
    `,
  });
  const result = scanReactSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(result.findings.some((finding) => finding.ruleId === 'TW-REACT007'));
});

test('Client Components may pass sensitive-shaped props to nested Client Components', () => {
  const snapshot = snapshotFromFiles({
    'src/components/account-panel.tsx': `
      'use client';
      import { SessionList } from './session-list';
      export function AccountPanel({ sessions, password, onRevokeSession }) {
        return <SessionList sessions={sessions} password={password} onRevokeSession={onRevokeSession} />;
      }
    `,
    'src/components/session-list.tsx': `
      'use client';
      export function SessionList({ sessions }) { return <div>{sessions.length}</div>; }
    `,
  });
  const result = scanReactSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-REACT007'));
});

test('Server Components may pass visual design tokens to Client Components', () => {
  const snapshot = snapshotFromFiles({
    'src/app/page.tsx': `
      import { ThemePreview } from '../components/theme-preview';
      export default function Page() {
        return <ThemePreview initialBackgroundColorToken="surface-primary" />;
      }
    `,
    'src/components/theme-preview.tsx': `
      'use client';
      export function ThemePreview({ initialBackgroundColorToken }) {
        return <div data-token={initialBackgroundColorToken} />;
      }
    `,
  });
  const result = scanReactSecurity(snapshot, profileProject(snapshot).profile);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-REACT007'));
});

test('safe React boundaries avoid client security candidates', () => {
  const result = scan(`
    'use client';
    export function SafeLink({ label }) {
      window.parent.postMessage({ ready: true }, 'https://app.example.test');
      window.addEventListener('message', (event) => {
        if (event.origin !== 'https://app.example.test') return;
        consume(event.data);
      });
      return <a href="/account" rel="noopener noreferrer" target="_blank">{label}</a>;
    }
  `);
  assert.deepEqual(result.findings, []);
});

test('noreferrer alone protects a new-tab link', () => {
  const result = scan(`
    'use client';
    export function ExternalLink() {
      return <a href="https://example.test" rel="noreferrer" target="_blank">Open</a>;
    }
  `);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-REACT006'));
});

test('ordinary component props, route builders, images, and array pushes are not navigation taint', () => {
  const result = scan(`
    'use client';
    export function ContentCard({ href, imageSrc, item, searchParams }) {
      const rows = [];
      rows.push(item);
      const accountPath = buildAccountPath(item.id);
      const { localizedLoginPath } = resolveLocalizedAuthFlowPaths({ nextPath: searchParams.get('next') });
      const preservedPath = preserveWidgetContext(accountPath, searchParams);
      const query = new URLSearchParams(searchParams.toString()).toString();
      router.replace(query ? \`/account?\${query}\` : '/account');
      return <><Link href={href}>Open</Link><Image src={imageSrc} alt="" /><Link href={accountPath}>Account</Link><Link href={localizedLoginPath}>Login</Link><Link href={preservedPath}>Preserved</Link></>;
    }
  `);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-REACT002'));
});

test('current pathname safely anchors browser-derived query navigation', () => {
  const result = scan(`
    'use client';
    export function Filters() {
      const pathname = usePathname();
      const searchParams = useSearchParams();
      const next = new URLSearchParams(searchParams.toString());
      next.set('mode', 'edit');
      const query = next.toString();
      router.replace(query ? \`${'${pathname}'}?${'${query}'}\` : pathname);
      return null;
    }
  `);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-REACT002'));
});

test('nested callbacks retain the current pathname as a same-origin anchor', () => {
  const result = scan(`
    'use client';
    export function Filters() {
      const pathname = usePathname();
      const searchParams = useSearchParams();
      const open = useCallback((itemId: string) => {
        const next = new URLSearchParams(searchParams.toString());
        next.set('id', itemId);
        const query = next.toString();
        router.replace(query ? \`${'${pathname}'}?${'${query}'}\` : pathname);
      }, [pathname, router, searchParams]);
      return <button onClick={() => open('item-1')}>Open</button>;
    }
  `);
  assert.ok(!result.findings.some((finding) => finding.ruleId === 'TW-REACT002'));
});
