'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Icon } from './icon.tsx';
export function Navigation() {
  const pathname = usePathname();
  const links = [
    { href: '/', label: 'Overview', icon: 'grid' },
    { href: '/audits', label: 'Audit history', icon: 'scan' },
    { href: '/projects', label: 'Projects', icon: 'folder' },
    { href: '/methodology', label: 'Methodology', icon: 'book' },
    { href: '/settings', label: 'Local settings', icon: 'settings' },
  ] as const;
  return (
    <nav className="navigation" aria-label="Main navigation">
      {links.map((link) => (
        <Link
          key={link.href}
          href={link.href}
          aria-label={link.label}
          className={
            pathname === link.href || (link.href === '/audits' && pathname.startsWith('/audits/'))
              ? 'nav-link active'
              : 'nav-link'
          }
        >
          <Icon name={link.icon} />
          <span>{link.label}</span>
          {link.href === '/' && <span className="nav-dot" />}
        </Link>
      ))}
    </nav>
  );
}
