'use client';
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { KeyboardEvent } from 'react';
import Link from 'next/link';
import type {
  Audit,
  AuditComparison,
  AuditEvent,
  Finding,
  Project,
  SecurityControlReviewDecision,
} from '../domain/types.ts';
import { Icon } from './icon.tsx';
import { Badge, EmptyState, SeverityBadge, StatusBadge, utcDate } from './ui.tsx';
import { NewAudit, mutate } from './new-audit.tsx';
import { FindingDetails } from './finding-details.tsx';
const tabs = [
  'Overview',
  'Findings',
  'Project map',
  'Checklist',
  'Investigations',
  'Dependencies',
  'Coverage',
  'Workflow',
] as const;
type Tab = (typeof tabs)[number];
const tabId = (label: Tab) => label.toLowerCase().replaceAll(' ', '-');
export function AuditWorkspace({
  initialAudit,
  initialEvents,
  initialWorkerOnline,
  projects,
  comparison,
}: {
  initialAudit: Audit;
  initialEvents: AuditEvent[];
  initialWorkerOnline: boolean;
  projects: Pick<Project, 'id' | 'name'>[];
  comparison?: AuditComparison;
}) {
  const [audit, setAudit] = useState(initialAudit);
  const [events, setEvents] = useState(initialEvents);
  const [workerOnline, setWorkerOnline] = useState(initialWorkerOnline);
  const [tab, setTab] = useState<Tab>('Overview');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [disposition, setDisposition] = useState('all');
  const [mapQuery, setMapQuery] = useState('');
  const [selected, setSelected] = useState<Finding | null>(null);
  const [error, setError] = useState('');
  const [note, setNote] = useState('');
  const [pending, setPending] = useState(false);
  const [controlPending, setControlPending] = useState<string | null>(null);
  const [controlNotes, setControlNotes] = useState<Record<string, string>>({});
  const [controlDecisions, setControlDecisions] = useState<
    Record<string, SecurityControlReviewDecision>
  >({});
  const report = audit.report;
  const findings = report?.findings ?? [];
  const active = ['queued', 'running'].includes(audit.status);
  const reviewable = ['awaiting_review', 'completed'].includes(audit.status);
  const refresh = useCallback(async () => {
    const response = await fetch(`/api/audits/${initialAudit.id}`, { cache: 'no-store' });
    if (!response.ok) throw new Error('Could not refresh this audit.');
    const result = (await response.json()) as {
      audit: Audit;
      events: AuditEvent[];
      workerOnline: boolean;
    };
    setAudit(result.audit);
    setEvents(result.events);
    setWorkerOnline(result.workerOnline);
  }, [initialAudit.id]);
  useEffect(() => {
    if (!active) return;
    const interval = setInterval(() => {
      void refresh().catch(() => setError('Live updates paused. Reload to reconnect.'));
    }, 2000);
    return () => clearInterval(interval);
  }, [active, refresh]);
  async function action(kind: 'publish' | 'cancel') {
    setPending(true);
    setError('');
    try {
      await mutate(`/api/audits/${audit.id}`, { action: kind, note });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Action failed.');
    } finally {
      setPending(false);
    }
  }
  async function reviewControl(controlId: string) {
    setControlPending(controlId);
    setError('');
    try {
      await mutate(`/api/audits/${audit.id}`, {
        action: 'review-control',
        controlId,
        decision: controlDecisions[controlId] ?? 'needs_follow_up',
        note: controlNotes[controlId] ?? '',
      });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Control review failed.');
    } finally {
      setControlPending(null);
    }
  }
  const visible = findings.filter(
    (finding) =>
      (severity === 'all' || finding.severity === severity) &&
      (disposition === 'all' || finding.disposition === disposition) &&
      `${finding.title} ${finding.category} ${finding.ruleId} ${finding.evidence[0]?.file ?? ''}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const completedScanners = report?.coverage
    ? report.coverage.filter((capability) => capability.status === 'COMPLETE').length
    : (report?.scanners.filter((scanner) => scanner.status === 'completed').length ?? 0);
  const needsReviewFindings = findings.filter((finding) => finding.disposition === 'needs_review');
  const reviewedFindings = findings.length - needsReviewFindings.length;
  const highFindings = needsReviewFindings.filter((finding) =>
    ['critical', 'high'].includes(finding.severity),
  ).length;
  const coverageTotal = report?.coverage?.length ?? report?.scanners.length ?? 0;
  const coverageGaps = Math.max(0, coverageTotal - completedScanners);
  const reviewSummary = active
    ? 'Audit in progress. Results update as scanners finish.'
    : highFindings > 0
      ? `${highFindings} high-priority ${highFindings === 1 ? 'candidate needs' : 'candidates need'} human review. ${coverageGaps} coverage ${coverageGaps === 1 ? 'gap remains' : 'gaps remain'} visible.`
      : needsReviewFindings.length > 0
        ? `${needsReviewFindings.length} ${needsReviewFindings.length === 1 ? 'candidate needs' : 'candidates need'} human review before this report is relied on.`
        : coverageGaps > 0
          ? `No pending candidate decisions. Review ${coverageGaps} coverage ${coverageGaps === 1 ? 'gap' : 'gaps'} before relying on this report.`
          : 'No pending candidate decisions in the captured scope.';
  const investigations = findings.filter((finding) => finding.analysis?.provider);
  const projectMapRows = useMemo(() => {
    const profile = report?.projectProfile;
    if (!profile) return [];
    const normalized = mapQuery.trim().toLowerCase();
    return profile.entrypoints
      .filter((entrypoint) =>
        normalized
          ? `${entrypoint.route ?? ''} ${entrypoint.name} ${entrypoint.file} ${entrypoint.methods.join(' ')}`
              .toLowerCase()
              .includes(normalized)
          : true,
      )
      .slice(0, 200);
  }, [mapQuery, report?.projectProfile]);
  const projectFactCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const fact of report?.projectProfile?.facts ?? [])
      counts.set(fact.kind, (counts.get(fact.kind) ?? 0) + 1);
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [report?.projectProfile]);
  const osvRun = report?.scanners.find((scanner) => scanner.id === 'osv');
  function handleTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    let nextIndex: number | null = null;
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
    else if (event.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') nextIndex = 0;
    else if (event.key === 'End') nextIndex = tabs.length - 1;
    if (nextIndex === null) return;
    const nextTab = tabs[nextIndex];
    if (!nextTab) return;
    event.preventDefault();
    setTab(nextTab);
    event.currentTarget.parentElement
      ?.querySelectorAll<HTMLButtonElement>('[role="tab"]')
      [nextIndex]?.focus();
  }
  const findingTable = (items: Finding[]) => (
    <div className="finding-list">
      {items.map((finding) => (
        <button className="finding-row" key={finding.id} onClick={() => setSelected(finding)}>
          <span className={`finding-indicator ${finding.severity}`}>
            <Icon
              name={
                finding.category === 'secrets'
                  ? 'lock'
                  : finding.category === 'ai-security'
                    ? 'branch'
                    : 'code'
              }
            />
          </span>
          <span className="finding-content">
            <span className="finding-row-title">{finding.title}</span>
            <span className="finding-location">
              {finding.evidence[0]?.file ?? 'Unknown location'}
              <span>· {finding.source}</span>
            </span>
          </span>
          <span className="finding-row-end">
            <SeverityBadge severity={finding.severity} />
            <span className="finding-state">{finding.disposition.replaceAll('_', ' ')}</span>
          </span>
          <Icon name="arrow" size={16} />
        </button>
      ))}
    </div>
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">EVIDENCE-LED SECURITY</div>
          <h1>{audit.projectName}</h1>
          <p className="subtitle">{reviewSummary}</p>
        </div>
        <NewAudit projects={projects} />
      </div>
      <div className="audit-meta">
        <StatusBadge status={audit.status} />
        <span>
          <Icon name="branch" size={14} />
          {report?.snapshotDigest.slice(0, 10) ?? 'Snapshot pending'}
        </span>
        <span>
          <Icon name="clock" size={14} />
          {utcDate(audit.createdAt)} UTC
        </span>
        <span className="mono">AUDIT {audit.id.slice(0, 8)}</span>
        {active ? (
          <span className="meta-right">
            <span className={workerOnline ? 'live-dot' : 'offline-dot'} />
            Worker {workerOnline ? 'online' : 'offline'}
          </span>
        ) : (
          <span className="meta-right">
            <Icon name="lock" size={13} /> Local report · {report?.publication ?? 'draft'}
          </span>
        )}
      </div>
      {error && (
        <div className="notice danger" role="alert">
          {error}
        </div>
      )}
      {audit.error && (
        <div className="notice danger">
          <Icon name="alert" />
          {audit.error}
        </div>
      )}
      {active && !workerOnline && (
        <div className="notice">
          <Icon name="terminal" />
          <span>
            The scan is queued. Start the separate worker with <code>npm run worker</code>. Closing
            this page does not remove the job.
          </span>
        </div>
      )}
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">
            Needs human review
            <Icon name="scan" />
          </div>
          <div className="stat-number">
            {needsReviewFindings.length.toString().padStart(2, '0')}
            <span>pending decisions</span>
          </div>
          <div className="stat-foot">{reviewedFindings} reviewed · never auto-confirmed</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            High-priority signals
            <Icon name="alert" />
          </div>
          <div className="stat-number amber">
            {highFindings.toString().padStart(2, '0')}
            <span>critical + high</span>
          </div>
          <div className="stat-foot">Severity does not imply exploitability</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            Files in snapshot
            <Icon name="folder" />
          </div>
          <div className="stat-number">
            {report?.filesAnalyzed ?? '—'}
            <span>bounded scope</span>
          </div>
          <div className="stat-foot">
            {report?.truncated ? 'Truncated · review coverage' : 'No target code was executed'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            Coverage gaps
            <Icon name="layers" />
          </div>
          <div className="stat-number">
            {coverageGaps}
            <span>of {coverageTotal || '—'} capabilities</span>
          </div>
          <div className="stat-foot">{completedScanners} complete · gaps stay visible</div>
        </div>
      </div>
      <div className="tabs" role="tablist" aria-label="Audit sections">
        {tabs.map((label, index) => (
          <button
            key={label}
            id={`audit-tab-${tabId(label)}`}
            role="tab"
            aria-selected={tab === label}
            aria-controls={`audit-panel-${tabId(label)}`}
            tabIndex={tab === label ? 0 : -1}
            className={tab === label ? 'tab active' : 'tab'}
            onClick={() => setTab(label)}
            onKeyDown={(event) => handleTabKeyDown(event, index)}
          >
            {label}
            {label === 'Findings' && <span className="tab-count">{findings.length}</span>}
            {label === 'Investigations' && investigations.length > 0 && (
              <span className="tab-count">{investigations.length}</span>
            )}
          </button>
        ))}
        <div className="tabs-spacer" />
        {report && (
          <a className="export-link" href={`/api/audits/${audit.id}/export?format=html`}>
            <Icon name="download" size={15} />
            Export report
          </a>
        )}
      </div>
      {tab === 'Overview' && (
        <div
          className="overview-grid"
          id="audit-panel-overview"
          role="tabpanel"
          aria-labelledby="audit-tab-overview"
        >
          <div className="main-column">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Prioritize the next review</h2>
                  <p>Signals grounded in your source snapshot.</p>
                </div>
                <button className="text-button" onClick={() => setTab('Findings')}>
                  View all
                  <Icon name="arrow" size={14} />
                </button>
              </div>
              {findings.length ? (
                findingTable(findings.slice(0, 5))
              ) : (
                <EmptyState
                  title={
                    active
                      ? 'The investigation is in progress'
                      : 'No candidates in the analyzed scope'
                  }
                >
                  <p>
                    {active
                      ? 'Scanner and workflow events will appear as the worker progresses.'
                      : 'This is not proof that the project is secure. Check what was actually analyzed.'}
                  </p>
                </EmptyState>
              )}
            </section>
            {comparison && (
              <section className="panel">
                <div className="panel-header">
                  <div>
                    <h2>Change since previous audit</h2>
                    <p className="mono small">Base {comparison.baseAuditId.slice(0, 8)}</p>
                  </div>
                  <Badge>SNAPSHOT DIFF</Badge>
                </div>
                <div className="panel-body">
                  <div className="detail-row">
                    <span>New findings</span>
                    <strong>{comparison.newFindings.length}</strong>
                  </div>
                  <div className="detail-row">
                    <span>Resolved findings</span>
                    <strong>{comparison.resolvedFindings.length}</strong>
                  </div>
                  <div className="detail-row">
                    <span>Unchanged findings</span>
                    <strong>{comparison.unchangedFindings.length}</strong>
                  </div>
                  <div className="detail-row">
                    <span>Severity changes</span>
                    <strong>{comparison.severityChanges.length}</strong>
                  </div>
                  <p className="small muted">
                    Fingerprint comparison is local and line-sensitive. A resolved signal is not
                    proof of remediation.
                  </p>
                </div>
              </section>
            )}
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Investigation activity</h2>
                  <p>Observable steps, not hidden model reasoning.</p>
                </div>
                <Badge>LANGGRAPH</Badge>
              </div>
              <ol className="timeline">
                {events.slice(-5).map((event) => (
                  <li key={event.id}>
                    <span className="timeline-dot">
                      <Icon name="check" size={11} />
                    </span>
                    <div>
                      <strong>{event.stage.replaceAll('_', ' ')}</strong>
                      <p>{event.message}</p>
                    </div>
                    <time>{utcDate(event.at).split(',').at(-1)}</time>
                  </li>
                ))}
              </ol>
            </section>
          </div>
          <aside className="right-column">
            <section className="panel trust-panel">
              <div className="panel-header">
                <h2>Trust &amp; coverage</h2>
                <Icon name="shield" />
              </div>
              <div className="trust-summary">
                <span className="trust-icon">
                  <Icon name="shield" size={24} />
                </span>
                <h3>Evidence, not a score.</h3>
                <p>
                  No invented safety percentage. Every conclusion has a source and a review status.
                </p>
              </div>
              <div className="detail-row">
                <span>Model inference</span>
                <Badge>
                  {report?.aiMode === 'ollama'
                    ? 'Local Ollama'
                    : report?.aiMode === 'openai'
                      ? 'OpenAI opt-in'
                      : 'Disabled'}
                </Badge>
              </div>
              <div className="detail-row">
                <span>Target execution</span>
                <strong>Never</strong>
              </div>
              <div className="detail-row">
                <span>HTTP probe</span>
                <strong>{report?.httpProbe ? 'One approved URL' : 'Not run'}</strong>
              </div>
              <div className="detail-row">
                <span>Automatic remediation</span>
                <strong>Off</strong>
              </div>
              <div className="detail-row">
                <span>Remote tracing</span>
                <strong>Off</strong>
              </div>
              <Link href="/methodology" className="method-link">
                Understand the methodology
                <Icon name="arrow" size={14} />
              </Link>
            </section>
            <section className="panel">
              <div className="panel-header">
                <h2>Scanner coverage</h2>
              </div>
              <div className="scanner-mini">
                {report?.scanners.map((scanner) => (
                  <div key={scanner.id}>
                    <span>
                      <span
                        className={scanner.status === 'completed' ? 'live-dot' : 'offline-dot'}
                      />
                      {scanner.name}
                    </span>
                    <small>{scanner.status}</small>
                  </div>
                )) ?? <p className="muted">Waiting for scanner results.</p>}
              </div>
            </section>
            <div className="scope-note">
              <Icon name="info" size={16} />
              <p>
                A static review is not a pentest or certification. Unknowns are part of the result.
              </p>
            </div>
          </aside>
        </div>
      )}
      {tab === 'Findings' && (
        <section
          className="panel"
          id="audit-panel-findings"
          role="tabpanel"
          aria-labelledby="audit-tab-findings"
        >
          <div className="filter-bar">
            <div className="search-field">
              <Icon name="search" size={17} />
              <input
                aria-label="Search findings"
                placeholder="Search findings, categories, or files…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
            <select
              aria-label="Filter severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <option value="all">All severities</option>
              {['critical', 'high', 'medium', 'low', 'info'].map((level) => (
                <option key={level}>{level}</option>
              ))}
            </select>
            <select
              aria-label="Filter review status"
              value={disposition}
              onChange={(event) => setDisposition(event.target.value)}
            >
              <option value="all">All review states</option>
              <option value="needs_review">Needs review</option>
              <option value="confirmed">Confirmed</option>
              <option value="accepted_risk">Accepted risk</option>
              <option value="false_positive">False positive</option>
            </select>
            <Badge>{visible.length} results</Badge>
          </div>
          {visible.length ? (
            findingTable(visible)
          ) : (
            <EmptyState title="No matching findings">
              <p>Try another filter. Absence of findings is not an assurance of safety.</p>
            </EmptyState>
          )}
        </section>
      )}
      {tab === 'Project map' && (
        <section
          className="panel"
          id="audit-panel-project-map"
          role="tabpanel"
          aria-labelledby="audit-tab-project-map"
        >
          <div className="panel-header">
            <div>
              <h2>Project map</h2>
              <p>Frameworks, request boundaries, and security-relevant source facts.</p>
            </div>
            <Badge tone={report?.projectProfile?.status === 'complete' ? 'success' : 'medium'}>
              {report?.projectProfile?.status ?? 'not generated'}
            </Badge>
          </div>
          {report?.projectProfile ? (
            <>
              <div className="panel-body">
                <div className="detail-row">
                  <span>Languages</span>
                  <strong>{report.projectProfile.languages.join(', ') || 'Unsupported'}</strong>
                </div>
                <div className="detail-row">
                  <span>Frameworks</span>
                  <strong>
                    {report.projectProfile.frameworks.map((item) => item.name).join(', ') ||
                      'No recognized framework'}
                  </strong>
                </div>
                <div className="detail-row">
                  <span>Structural coverage</span>
                  <strong>
                    {report.projectProfile.filesAnalyzed} files ·{' '}
                    {report.projectProfile.nodesAnalyzed} AST nodes
                  </strong>
                </div>
                <div className="checklist-summary">
                  {projectFactCounts.slice(0, 12).map(([kind, count]) => (
                    <Badge key={kind}>
                      {kind.replaceAll('-', ' ')} {count}
                    </Badge>
                  ))}
                </div>
                {report.projectProfile.issues.length > 0 && (
                  <ul className="limitations">
                    {report.projectProfile.issues.map((issue) => (
                      <li key={issue}>{issue}</li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="filter-bar">
                <div className="search-field">
                  <Icon name="search" size={17} />
                  <input
                    aria-label="Search project entry points"
                    placeholder="Search routes, methods, or source files…"
                    value={mapQuery}
                    onChange={(event) => setMapQuery(event.target.value)}
                  />
                </div>
                <Badge>
                  {projectMapRows.length}
                  {report.projectProfile.entrypoints.length > 200 ? ' shown' : ' entry points'}
                </Badge>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Boundary</th>
                      <th>Method</th>
                      <th>Route / action</th>
                      <th>Source</th>
                      <th>Parameters</th>
                    </tr>
                  </thead>
                  <tbody>
                    {projectMapRows.map((entrypoint) => (
                      <tr key={entrypoint.id}>
                        <td>{entrypoint.kind.replaceAll('-', ' ')}</td>
                        <td className="mono">{entrypoint.methods.join(', ') || 'ACTION'}</td>
                        <td className="strong mono">{entrypoint.route ?? entrypoint.name}</td>
                        <td className="mono small">
                          {entrypoint.file}:{entrypoint.line}
                        </td>
                        <td>{entrypoint.dynamicParameters.join(', ') || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {projectMapRows.length === 0 && (
                <EmptyState title="No matching entry points">
                  <p>Try another search or inspect the structural coverage issues above.</p>
                </EmptyState>
              )}
            </>
          ) : (
            <EmptyState title="Project map not generated">
              <p>Run a new audit with the current release.</p>
            </EmptyState>
          )}
        </section>
      )}
      {tab === 'Dependencies' && (
        <section
          className="panel"
          id="audit-panel-dependencies"
          role="tabpanel"
          aria-labelledby="audit-tab-dependencies"
        >
          <div className="panel-header">
            <div>
              <h2>Dependency inventory</h2>
              <p>Resolved lockfile versions where available; declared ranges remain visible.</p>
            </div>
            <Badge tone={osvRun?.status === 'completed' ? 'success' : 'medium'}>
              OSV {osvRun?.status ?? 'not run'}
            </Badge>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Requested version</th>
                  <th>Resolved version</th>
                  <th>Relationship</th>
                  <th>Scope</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {report?.dependencies.map((dependency) => (
                  <tr
                    key={`${dependency.manifest}:${dependency.scope}:${dependency.name}:${dependency.resolvedVersion ?? dependency.requestedVersion}`}
                  >
                    <td className="strong mono">{dependency.name}</td>
                    <td className="mono">{dependency.requestedVersion}</td>
                    <td className="mono">{dependency.resolvedVersion ?? 'Not resolved'}</td>
                    <td>{dependency.relationship ?? 'unknown'}</td>
                    <td>{dependency.scope}</td>
                    <td className="mono small">{dependency.lockfile ?? dependency.manifest}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel-footer">
            A known vulnerable version does not prove that vulnerable code is reachable or
            exploitable. Check OSV status and advisory freshness in Coverage.
          </div>
        </section>
      )}
      {tab === 'Checklist' && (
        <section
          className="panel"
          id="audit-panel-checklist"
          role="tabpanel"
          aria-labelledby="audit-tab-checklist"
        >
          <div className="panel-header">
            <div>
              <h2>Security control checklist</h2>
              <p>
                Evidence, gaps, and unknowns remain separate. Evidenced does not mean globally safe.
              </p>
            </div>
            <Badge>{report?.checklist?.packVersion ?? 'not generated'}</Badge>
          </div>
          {report?.checklist ? (
            <>
              <div className="panel-body checklist-summary">
                {Object.entries(report.checklist.summary).map(([status, count]) => (
                  <Badge
                    key={status}
                    tone={
                      status === 'EVIDENCED'
                        ? 'success'
                        : status === 'GAP_CANDIDATE' || status === 'FAILED'
                          ? 'medium'
                          : 'neutral'
                    }
                  >
                    {status.replaceAll('_', ' ')} {count}
                  </Badge>
                ))}
              </div>
              {report.checklist.controls.map((control) => (
                <div className="coverage-row" key={control.id}>
                  <div className="row spread">
                    <div>
                      <span className="small muted mono">{control.id}</span>
                      <h3>{control.title}</h3>
                    </div>
                    <Badge
                      tone={
                        control.status === 'EVIDENCED'
                          ? 'success'
                          : control.status === 'GAP_CANDIDATE' || control.status === 'FAILED'
                            ? 'medium'
                            : 'neutral'
                      }
                    >
                      {control.status.replaceAll('_', ' ')}
                    </Badge>
                  </div>
                  <p>{control.rationale}</p>
                  <p className="small muted">
                    <strong>Verify:</strong> {control.verification}
                  </p>
                  {control.review && (
                    <div className="notice">
                      <Icon name="check" />
                      <span>
                        Human assessment: {control.review.decision.replaceAll('_', ' ')} —{' '}
                        {control.review.note}
                      </span>
                    </div>
                  )}
                  {reviewable && (
                    <details>
                      <summary className="small strong">Record human control assessment</summary>
                      <div className="panel-body">
                        <label htmlFor={`control-decision-${control.id}`}>Decision</label>
                        <select
                          id={`control-decision-${control.id}`}
                          value={
                            controlDecisions[control.id] ??
                            control.review?.decision ??
                            'needs_follow_up'
                          }
                          onChange={(event) =>
                            setControlDecisions((current) => ({
                              ...current,
                              [control.id]: event.target.value as SecurityControlReviewDecision,
                            }))
                          }
                        >
                          <option value="verified_external">Verified external evidence</option>
                          <option value="accepted_gap">Accepted gap</option>
                          <option value="not_applicable">Not applicable</option>
                          <option value="needs_follow_up">Needs follow-up</option>
                        </select>
                        <label htmlFor={`control-note-${control.id}`}>Evidence and rationale</label>
                        <textarea
                          id={`control-note-${control.id}`}
                          rows={3}
                          value={controlNotes[control.id] ?? control.review?.note ?? ''}
                          onChange={(event) =>
                            setControlNotes((current) => ({
                              ...current,
                              [control.id]: event.target.value,
                            }))
                          }
                        />
                        <button
                          className="button"
                          disabled={
                            controlPending === control.id ||
                            (controlNotes[control.id] ?? control.review?.note ?? '').trim().length <
                              12
                          }
                          onClick={() => void reviewControl(control.id)}
                        >
                          {controlPending === control.id ? 'Saving…' : 'Save control assessment'}
                        </button>
                      </div>
                    </details>
                  )}
                </div>
              ))}
            </>
          ) : (
            <EmptyState title="Checklist not generated">
              <p>Run a new audit with the current release.</p>
            </EmptyState>
          )}
        </section>
      )}
      {tab === 'Investigations' && (
        <section
          className="panel"
          id="audit-panel-investigations"
          role="tabpanel"
          aria-labelledby="audit-tab-investigations"
        >
          <div className="panel-header">
            <div>
              <h2>Bounded AI investigations</h2>
              <p>Model context supports review; deterministic findings remain unchanged.</p>
            </div>
            <Badge>{report?.aiMode ?? 'disabled'}</Badge>
          </div>
          {report?.aiUsage && (
            <div className="panel-body checklist-summary">
              <Badge>{report.aiUsage.calls} calls</Badge>
              <Badge>{report.aiUsage.inputTokens} input tokens</Badge>
              <Badge>{report.aiUsage.outputTokens} output tokens</Badge>
              <Badge>{report.aiUsage.cacheHits} cache hits</Badge>
              <Badge>{report.aiUsage.contextIdsSent?.length ?? 0} context IDs</Badge>
              {report.aiUsage.approximateCostUsd !== undefined && (
                <Badge>${report.aiUsage.approximateCostUsd.toFixed(4)} estimated</Badge>
              )}
            </div>
          )}
          {investigations.length ? (
            <div className="finding-list">
              {investigations.map((finding) => (
                <button
                  className="finding-row"
                  key={finding.id}
                  onClick={() => setSelected(finding)}
                >
                  <span className="finding-indicator medium">
                    <Icon name="branch" />
                  </span>
                  <span className="finding-content">
                    <span className="finding-row-title">{finding.title}</span>
                    <span className="finding-location">
                      {finding.analysis?.assessment.replaceAll('_', ' ')} · confidence{' '}
                      {finding.analysis?.confidence ?? 'unknown'}
                    </span>
                  </span>
                  <span className="finding-row-end">
                    <Badge>{finding.analysis?.provider}</Badge>
                    <span className="finding-state">
                      {finding.analysis?.cached ? 'cache hit' : 'fresh'}
                    </span>
                  </span>
                  <Icon name="arrow" size={16} />
                </button>
              ))}
            </div>
          ) : (
            <EmptyState title="No model investigation was performed">
              <p>
                Disabled mode is fully functional. Enable local Ollama or explicitly configure
                OpenAI only when contextual analysis is worth the cost.
              </p>
            </EmptyState>
          )}
        </section>
      )}
      {tab === 'Coverage' && (
        <div
          className="coverage-grid"
          id="audit-panel-coverage"
          role="tabpanel"
          aria-labelledby="audit-tab-coverage"
        >
          <section className="panel">
            <div className="panel-header">
              <h2>What actually ran</h2>
            </div>
            {(report?.coverage ?? report?.scanners ?? []).map((capability) => (
              <div className="coverage-row" key={capability.id}>
                <div className="row spread">
                  <strong>{'label' in capability ? capability.label : capability.name}</strong>
                  <Badge
                    tone={
                      ('status' in capability && capability.status === 'COMPLETE') ||
                      capability.status === 'completed'
                        ? 'success'
                        : 'neutral'
                    }
                  >
                    {capability.status}
                  </Badge>
                </div>
                <p>{capability.detail}</p>
                <span className="small muted">
                  {capability.findings ?? 0} findings
                  {'durationMs' in capability ? ` · ${capability.durationMs} ms` : ''}{' '}
                  {capability.version ? ` · ${capability.version}` : ''}
                </span>
              </div>
            ))}
          </section>
          {report?.scopePreflight && (
            <section className="panel">
              <div className="panel-header">
                <h2>Pre-audit scope estimate</h2>
                <Badge tone={report.scopePreflight.predictedTruncated ? 'medium' : 'success'}>
                  {report.scopePreflight.predictedTruncated ? 'PARTIAL EXPECTED' : 'WITHIN LIMITS'}
                </Badge>
              </div>
              <div className="panel-body">
                <div className="detail-row">
                  <span>Supported source</span>
                  <strong>
                    {report.scopePreflight.supportedFiles} files ·{' '}
                    {(report.scopePreflight.supportedBytes / (1024 * 1024)).toFixed(2)} MiB
                  </strong>
                </div>
                <div className="detail-row">
                  <span>Snapshot limits</span>
                  <strong>
                    {report.scopePreflight.limits.files} files ·{' '}
                    {(report.scopePreflight.limits.totalBytes / (1024 * 1024)).toFixed(0)} MiB
                  </strong>
                </div>
                <div className="detail-row">
                  <span>Truncation approval</span>
                  <strong>
                    {report.scopePreflight.truncationApproved ? 'Explicit' : 'Not needed'}
                  </strong>
                </div>
                {report.scopePreflight.reasons.length > 0 && (
                  <p className="small muted">
                    Expected limits: {report.scopePreflight.reasons.join(', ')}.
                  </p>
                )}
                {report.scopePreflight.scopeFiles && (
                  <p className="small muted">
                    Runtime rules: {report.scopePreflight.scopeFiles.runtime} files. Test/example
                    code retained only for secret detection:{' '}
                    {report.scopePreflight.scopeFiles.test +
                      report.scopePreflight.scopeFiles.example}{' '}
                    files.
                  </p>
                )}
              </div>
            </section>
          )}
          {report?.httpProbe && (
            <section className="panel">
              <div className="panel-header">
                <h2>Observed HTTP response</h2>
                <Badge tone="success">RUNTIME EVIDENCE</Badge>
              </div>
              <div className="panel-body">
                <div className="detail-row">
                  <span>Target</span>
                  <code>{report.httpProbe.finalUrl}</code>
                </div>
                <div className="detail-row">
                  <span>Request</span>
                  <strong>
                    {report.httpProbe.method} · HTTP {report.httpProbe.statusCode}
                  </strong>
                </div>
                <div className="detail-row">
                  <span>Redirects</span>
                  <strong>{report.httpProbe.redirects}</strong>
                </div>
                <div className="detail-row">
                  <span>Retained headers / cookie metadata</span>
                  <strong>
                    {Object.keys(report.httpProbe.headers).length} /{' '}
                    {report.httpProbe.cookies.length}
                  </strong>
                </div>
                {report.httpProbe.redirectChain?.map((redirect, index) => (
                  <p
                    className="small muted"
                    key={`${redirect.statusCode}:${redirect.from}:${redirect.to}`}
                  >
                    Redirect {index + 1}: HTTP {redirect.statusCode} · {redirect.from} →{' '}
                    {redirect.to}
                  </p>
                ))}
                <p className="small muted">
                  One bounded observation at {utcDate(report.httpProbe.observedAt)} UTC. A synthetic
                  external Origin tests passive CORS behavior. No crawl, mutation, or exploit was
                  performed.
                </p>
              </div>
            </section>
          )}
          {report?.projectProfile && (
            <section className="panel">
              <div className="panel-header">
                <h2>Project structure</h2>
                <Badge tone={report.projectProfile.status === 'complete' ? 'success' : 'medium'}>
                  {report.projectProfile.status}
                </Badge>
              </div>
              <div className="panel-body">
                <div className="detail-row">
                  <span>Frameworks</span>
                  <strong>
                    {report.projectProfile.frameworks.map((item) => item.name).join(', ') ||
                      'None detected'}
                  </strong>
                </div>
                <div className="detail-row">
                  <span>Entry points</span>
                  <strong>{report.projectProfile.entrypoints.length}</strong>
                </div>
                <div className="detail-row">
                  <span>Symbols / call edges</span>
                  <strong>
                    {report.projectProfile.symbols.length} / {report.projectProfile.calls.length}
                  </strong>
                </div>
                <div className="detail-row">
                  <span>Security facts</span>
                  <strong>{report.projectProfile.facts.length}</strong>
                </div>
                {report.projectProfile.issues.length > 0 && (
                  <p className="small muted">
                    {report.projectProfile.issues.length} issue(s) keep structural coverage partial.
                  </p>
                )}
              </div>
            </section>
          )}
          <section className="panel">
            <div className="panel-header">
              <h2>Boundaries &amp; exclusions</h2>
            </div>
            <div className="panel-body">
              <h3 className="section-label">Skipped scope</h3>
              {Object.entries(report?.skipped ?? {}).map(([reason, count]) => (
                <div className="detail-row" key={reason}>
                  <span>{reason.replaceAll('-', ' ')}</span>
                  <strong>{count}</strong>
                </div>
              ))}
              <h3 className="section-label">Limitations</h3>
              <ul className="limitations">
                {report?.limitations.map((limitation) => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </div>
          </section>
        </div>
      )}
      {tab === 'Workflow' && (
        <section
          className="panel"
          id="audit-panel-workflow"
          role="tabpanel"
          aria-labelledby="audit-tab-workflow"
        >
          <div className="panel-header">
            <div>
              <h2>Audit graph</h2>
              <p>
                Persistent checkpoints, parallel scanners, bounded investigation, human publication
                review.
              </p>
            </div>
            <Badge>ONE THREAD PER AUDIT</Badge>
          </div>
          <div className="workflow">
            <div className="graph-node done">
              <Icon name="folder" />
              Capture bounded snapshot
            </div>
            <div className="graph-connector">↓</div>
            <div className="graph-parallel">
              {[
                'project_profile',
                'ast_security',
                'patterns',
                'posture',
                'semgrep',
                'gitleaks',
                'http_probe',
                'inventory',
              ].map((stage) => (
                <div
                  key={stage}
                  className={`graph-node ${events.some((event) => event.stage === stage) ? 'done' : ''}`}
                >
                  <Icon name="scan" />
                  {stage}
                </div>
              ))}
            </div>
            <div className="graph-connector">↓</div>
            <div className="graph-node">Normalize &amp; prioritize candidates</div>
            <div className="graph-connector">↓</div>
            <div className="graph-node loop">
              <Icon name="branch" />
              Read → assess → request context <span>≤ 2 rounds / finding · ≤ 12 findings</span>
            </div>
            <div className="graph-connector">↓</div>
            <div className={`graph-node ${audit.status === 'awaiting_review' ? 'waiting' : ''}`}>
              <Icon name="lock" />
              Human publication review <span>interrupt() → Command(resume)</span>
            </div>
            <div className="graph-connector">↓</div>
            <div className="graph-node">Publish with unresolved findings intact</div>
          </div>
        </section>
      )}
      {audit.status === 'awaiting_review' && (
        <section className="publication-panel">
          <div>
            <div className="eyebrow">HUMAN-IN-THE-LOOP</div>
            <h2>Publish an accountable report.</h2>
            <p>
              {reviewedFindings}/{findings.length} candidates reviewed · {coverageGaps} coverage
              {coverageGaps === 1 ? ' gap' : ' gaps'}. Publication records your acknowledgement; it
              does not confirm unresolved findings.
            </p>
          </div>
          <div className="publication-form">
            <label htmlFor="publication-note">Publication review note</label>
            <textarea
              id="publication-note"
              rows={2}
              maxLength={2000}
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Summarize what you reviewed and any remaining unknowns."
            />
            <button
              className="button primary"
              disabled={pending || note.trim().length < 12}
              onClick={() => action('publish')}
            >
              Acknowledge gaps and publish
              <Icon name="arrow" size={16} />
            </button>
          </div>
        </section>
      )}
      <footer className="audit-footer">
        <span>
          <Icon name="lock" size={13} />
          Evidence stays in local storage. Redaction is best effort.
        </span>
        <div className="row gap">
          {report && (
            <>
              <a href={`/api/audits/${audit.id}/export?format=json`}>JSON</a>
              <a href={`/api/audits/${audit.id}/export?format=md`}>Markdown</a>
              <a href={`/api/audits/${audit.id}/export?format=sarif`}>SARIF</a>
              <a href={`/api/audits/${audit.id}/export?format=sbom`}>CycloneDX SBOM</a>
              <a href={`/api/audits/${audit.id}/export?format=bundle`}>Codex bundle</a>
            </>
          )}
          {['queued', 'running', 'awaiting_review'].includes(audit.status) && (
            <button
              className="text-button danger-text"
              onClick={() => action('cancel')}
              disabled={pending}
            >
              Cancel audit
            </button>
          )}
        </div>
      </footer>
      {selected && (
        <FindingDetails
          finding={selected}
          auditId={audit.id}
          reviewable={reviewable}
          close={() => setSelected(null)}
          refresh={refresh}
        />
      )}
    </>
  );
}
