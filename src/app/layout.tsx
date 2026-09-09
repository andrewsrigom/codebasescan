import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import Link from 'next/link';
import { Icon } from '../components/icon.tsx';
import { Navigation } from '../components/navigation.tsx';
import './globals.css';
export const metadata: Metadata = {
  title: 'Traceward · Security review workbench',
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
          <Link href="/" className="brand" aria-label="Traceward overview">
            <span className="brand-mark">
              <Icon name="shield" size={23} />
            </span>
            <span>
              traceward <span className="brand-sub">SECURITY WORKBENCH</span>
            </span>
          </Link>
          <div className="workspace-label">YOUR WORKSPACE</div>
          <div className="workspace-pill">
            <span className="avatar">L</span>
            <div>
              <strong>Local workspace</strong>
              <small>Single-user · private</small>
            </div>
            <span className="live-dot" />
          </div>
          <Navigation />
          <div className="sidebar-bottom">
            <div className="sidebar-version">v0.2.0</div>
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
            <div className="topbar-right">
              <span className="pill neutral">
                <span className="live-dot" />
                LOOPBACK ONLY
              </span>
              <span className="top-avatar" aria-hidden="true">
                L
              </span>
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
