'use client';

import { useMemo } from 'react';
import type { Dependency, Finding, Severity } from '../domain/types.ts';
import { groupDependencyAdvisories } from '../domain/dependency-advisories.ts';
import { Badge, EmptyState, SeverityBadge } from './ui.tsx';

function severitySummary(counts: Record<Severity, number>): string {
  return (['critical', 'high', 'medium', 'low', 'info'] as const)
    .filter((severity) => counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${severity}`)
    .join(' · ');
}

export function DependencyAdvisoryReport({
  findings,
  dependencies,
  onSelect,
}: {
  findings: Finding[];
  dependencies: Dependency[];
  onSelect: (finding: Finding) => void;
}) {
  const groups = useMemo(
    () => groupDependencyAdvisories(findings, dependencies),
    [dependencies, findings],
  );
  const advisoryCount = groups.reduce((total, group) => total + group.advisoryCount, 0);
  const directPackages = groups.filter((group) => group.relationship === 'direct').length;
  const referencedPackages = groups.filter((group) => group.reachability === 'referenced').length;
  const completeVersionPlans = groups
    .flatMap((group) => group.versionPlans)
    .filter((plan) => plan.advisoryCount > 0 && plan.fixCoverage === plan.advisoryCount).length;

  if (groups.length === 0)
    return (
      <div className="dependency-remediation">
        <EmptyState title="No dependency advisory groups">
          <p>No OSV finding is attached to the resolved dependency inventory.</p>
        </EmptyState>
      </div>
    );

  return (
    <div className="dependency-remediation">
      <div className="stat-grid dependency-stats">
        <div className="stat-card">
          <div className="stat-label">Affected packages</div>
          <div className="stat-number">{groups.length}</div>
          <div className="stat-foot">Grouped from {advisoryCount} individual advisories</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Direct dependencies</div>
          <div className="stat-number">{directPackages}</div>
          <div className="stat-foot">Upgrade in the project manifest</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Source referenced</div>
          <div className="stat-number">{referencedPackages}</div>
          <div className="stat-foot">Import evidence only; execution is unverified</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Complete fix evidence</div>
          <div className="stat-number">{completeVersionPlans}</div>
          <div className="stat-foot">Version plans with same-major fixes for every advisory</div>
        </div>
      </div>

      <div className="dependency-plan-list">
        {groups.map((group) => (
          <article className="dependency-group" key={group.package}>
            <header className="dependency-group-header">
              <div>
                <h3 className="mono">{group.package}</h3>
                <p>
                  {group.advisoryCount} {group.advisoryCount === 1 ? 'advisory' : 'advisories'} ·{' '}
                  {group.affectedVersions.length}{' '}
                  {group.affectedVersions.length === 1 ? 'affected version' : 'affected versions'}
                </p>
              </div>
              <div className="dependency-group-badges">
                <SeverityBadge severity={group.highestSeverity} />
                <Badge tone={group.relationship === 'direct' ? 'medium' : 'neutral'}>
                  {group.relationship}
                </Badge>
                <Badge tone={group.reachability === 'referenced' ? 'success' : 'neutral'}>
                  {group.reachability.replaceAll('_', ' ')}
                </Badge>
              </div>
            </header>

            <div className="dependency-version-plans">
              {group.versionPlans.map((plan) => (
                <div className="dependency-version-plan" key={plan.version}>
                  <div className="dependency-version-heading">
                    <code>
                      {group.package}@{plan.version}
                    </code>
                    <span>{severitySummary(plan.severityCounts)}</span>
                  </div>
                  <p>{plan.action}</p>
                  {plan.parentChains.length > 0 && (
                    <div className="dependency-parent-chains">
                      {plan.parentChains.map((chain) => (
                        <code key={chain.join('\u0000')}>{chain.join(' → ')}</code>
                      ))}
                    </div>
                  )}
                  <div className="dependency-version-meta">
                    {plan.fixCandidate ? (
                      <Badge tone={plan.fixCoverage === plan.advisoryCount ? 'success' : 'medium'}>
                        candidate {plan.fixCandidate} · {plan.fixCoverage}/{plan.advisoryCount}
                      </Badge>
                    ) : (
                      <Badge tone="medium">no same-major candidate</Badge>
                    )}
                    {plan.scopes.map((scope) => (
                      <Badge key={scope}>{scope}</Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <details className="dependency-advisory-details">
              <summary>
                Review {group.pendingCount} pending{' '}
                {group.pendingCount === 1 ? 'advisory' : 'advisories'}
              </summary>
              <div className="dependency-advisory-list">
                {group.findings.map((finding) => (
                  <button key={finding.id} type="button" onClick={() => onSelect(finding)}>
                    <span>
                      <strong>{finding.title}</strong>
                      <small className="mono">{finding.ruleId}</small>
                    </span>
                    <SeverityBadge severity={finding.severity} />
                  </button>
                ))}
              </div>
            </details>
          </article>
        ))}
      </div>
    </div>
  );
}
