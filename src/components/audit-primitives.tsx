import type { ReactNode } from 'react';
import type { AuditStatus, Severity } from '../domain/types.ts';
import { Badge as BaseBadge } from './ui/badge.tsx';

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return (
    <BaseBadge variant="outline" className={`pill ${tone}`}>
      {children}
    </BaseBadge>
  );
}
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge tone={severity}>
      <span className="severity-dot" />
      {severity}
    </Badge>
  );
}
export function StatusBadge({ status }: { status: AuditStatus }) {
  return (
    <Badge
      tone={
        status === 'completed'
          ? 'success'
          : status === 'failed'
            ? 'high'
            : status === 'awaiting_review'
              ? 'medium'
              : 'neutral'
      }
    >
      {status.replaceAll('_', ' ')}
    </Badge>
  );
}
export function EmptyState({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-symbol">◎</div>
      <h2>{title}</h2>
      <div>{children}</div>
    </div>
  );
}
export function utcDate(value: string): string {
  return new Date(value).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'UTC',
  });
}
