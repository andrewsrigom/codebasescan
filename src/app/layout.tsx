import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import Link from 'next/link';
import { Icon } from '../components/icon.tsx';
import { Navigation } from '../components/navigation.tsx';
import './globals.css';

export const metadata: Metadata = {
  title: 'CodebaseScan · Security review workbench',
  description: 'Local-first, evidence-led security review. Your code stays in your workspace.',
  robots: { index: false, follow: false },
};
export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a href="#main" className="skip-link">
          Skip to content
        </a>
        <aside className="sidebar">
          <Link href="/" className="brand" aria-label="CodebaseScan overview">
            <span className="brand-mark">
              <Icon name="shield" size={23} />
            </span>
            <span>
              codebasescan <span className="brand-sub">SECURITY WORKBENCH</span>
            </span>
          </Link>
          <Navigation />
          <div className="sidebar-bottom">
            <div className="sidebar-version">v0.2.1</div>
          </div>
        </aside>
        <div className="app-shell">
          <header className="topbar">
            <div className="breadcrumb">
              <Icon name="layers" size={16} />
              <span>Workspace</span>
              <span>/</span>
              <strong>Security review</strong>
            </div>
          </header>
          <main id="main" className="main-content">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
