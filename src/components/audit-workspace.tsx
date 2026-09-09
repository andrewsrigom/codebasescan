'use client';
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import type { Audit, AuditEvent, Finding, Project } from '../domain/types.ts';
import { Icon } from './icon.tsx';
import { Badge, EmptyState, SeverityBadge, StatusBadge, utcDate } from './ui.tsx';
import { NewAudit, mutate } from './new-audit.tsx';
import { FindingDetails } from './finding-details.tsx';
const tabs = ['Overview', 'Findings', 'Dependencies', 'Coverage', 'Workflow'] as const;
type Tab = (typeof tabs)[number];
export function AuditWorkspace({ initialAudit, initialEvents, initialWorkerOnline, projects }: {
  initialAudit: Audit;
  initialEvents: AuditEvent[];
  initialWorkerOnline: boolean;
  projects: Pick<Project, 'id' | 'name'>[];
}) {
  const [audit, setAudit] = useState(initialAudit);
  const [events, setEvents] = useState(initialEvents);
  const [workerOnline, setWorkerOnline] = useState(initialWorkerOnline);
  const [tab, setTab] = useState<Tab>('Overview');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selected, setSelected] = useState<Finding | null>(null);
  const [error, setError] = useState('');
  const [note, setNote] = useState('');
  const [pending, setPending] = useState(false);
  const report = audit.report;
  const findings = report?.findings ?? [];
  const active = ['queued', 'running'].includes(audit.status);
  const reviewable = ['awaiting_review', 'completed'].includes(audit.status);
  const refresh = useCallback(async () => {
    const response = await fetch(`/api/audits/${initialAudit.id}`, { cache: 'no-store' });
    if (!response.ok)
      throw new Error('Could not refresh this audit.');
    const result = await response.json() as {
      audit: Audit;
      events: AuditEvent[];
      workerOnline: boolean;
    };
    setAudit(result.audit);
    setEvents(result.events);
    setWorkerOnline(result.workerOnline);
  }, [initialAudit.id]);
  useEffect(() => {
    if (!active)
      return;
    const interval = setInterval(() => { void refresh().catch(() => setError('Live updates paused. Reload to reconnect.')); }, 2000);
    return () => clearInterval(interval);
  }, [active, refresh]);
  async function action(kind: 'publish' | 'cancel') {
    setPending(true);
    setError('');
    try {
      await mutate(`/api/audits/${audit.id}`, { action: kind, note });
      await refresh();
    }
    catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Action failed.');
    }
    finally {
      setPending(false);
    }
  }
  const visible = findings.filter((finding) => (severity === 'all' || finding.severity === severity) && `${finding.title} ${finding.category} ${finding.evidence[0]?.file ?? ''}`.toLowerCase().includes(query.toLowerCase()));
  const completedScanners = report?.scanners.filter((scanner) => scanner.status === 'completed').length ?? 0;
  const openFindings = findings.filter((finding) => !['false_positive', 'accepted_risk'].includes(finding.disposition));
  const highFindings = openFindings.filter((finding) => ['critical', 'high'].includes(finding.severity)).length;
  const findingTable = (items: Finding[]) => <div className="finding-list">
    {items.map((finding) => <button className="finding-row" key={finding.id} onClick={() => setSelected(finding)}>
      <span className={`finding-indicator ${finding.severity}`}>
        <Icon
          name={finding.category === 'secrets' ? 'lock' : finding.category === 'ai-security' ? 'branch' : 'code'}
        />
      </span>
      <span className="finding-content">
        <span className="finding-row-title">
          {finding.title}
        </span>
        <span className="finding-location">
          {finding.evidence[0]?.file ?? 'Unknown location'}
          <span>
            ·
            {' '}{finding.source}
          </span>
        </span>
      </span>
      <span className="finding-row-end">
        <SeverityBadge severity={finding.severity} />
        <span className="finding-state">
          {finding.disposition.replaceAll('_', ' ')}
        </span>
      </span>
      <Icon name="arrow" size={16} />
    </button>)}
  </div>;
  return <>
    <div className="page-heading">
      <div>
        <div className="eyebrow">
          EVIDENCE-LED SECURITY
        </div>
        <h1>
          {audit.projectName}
        </h1>
        <p className="subtitle">
          Understand the finding. Inspect the evidence. Make the call.
        </p>
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
        {utcDate(audit.createdAt)}
        {' '}UTC
      </span>
      <span className="mono">
        AUDIT
        {' '}{audit.id.slice(0, 8)}
      </span>
      <span className="meta-right">
        <span className={workerOnline ? 'live-dot' : 'offline-dot'} />
        Worker
        {' '}{workerOnline ? 'online' : 'offline'}
      </span>
    </div>
    {error && <div className="notice danger" role="alert">
      {error}
    </div>}
    {audit.error && <div className="notice danger">
      <Icon name="alert" />
      {audit.error}
    </div>}
    {active && !workerOnline && <div className="notice">
      <Icon name="terminal" />
      <span>
        The scan is queued. Start the separate worker with
        {' '}<code>
          npm run worker
        </code>
        . Closing this page does not remove the job.
      </span>
    </div>}
    <div className="stat-grid">
      <div className="stat-card">
        <div className="stat-label">
          Open review candidates
          <Icon name="scan" />
        </div>
        <div className="stat-number">
          {openFindings.length.toString().padStart(2, '0')}
          <span>
            to investigate
          </span>
        </div>
        <div className="stat-foot">
          Not automatically confirmed
        </div>
      </div>
      <div className="stat-card">
        <div className="stat-label">
          High-priority signals
          <Icon name="alert" />
        </div>
        <div className="stat-number amber">
          {highFindings.toString().padStart(2, '0')}
          <span>
            critical + high
          </span>
        </div>
        <div className="stat-foot">
          Severity does not imply exploitability
        </div>
      </div>
      <div className="stat-card">
        <div className="stat-label">
          Files in snapshot
          <Icon name="folder" />
        </div>
        <div className="stat-number">
          {report?.filesAnalyzed ?? '—'}
          <span>
            bounded scope
          </span>
        </div>
        <div className="stat-foot">
          {report?.truncated ? 'Truncated · review coverage' : 'No target code was executed'}
        </div>
      </div>
      <div className="stat-card">
        <div className="stat-label">
          Completed scanner checks
          <Icon name="layers" />
        </div>
        <div className="stat-number">
          {completedScanners}
          <span>
            /
            {report?.scanners.length ?? 4}
          </span>
        </div>
        <div className="stat-foot">
          Skipped checks stay visible
        </div>
      </div>
    </div>
    <div className="tabs" role="tablist" aria-label="Audit sections">
      {tabs.map((label) => <button
        key={label}
        role="tab"
        aria-selected={tab === label}
        className={tab === label ? 'tab active' : 'tab'}
        onClick={() => setTab(label)}
      >
        {label}
        {label === 'Findings' && <span className="tab-count">
          {findings.length}
        </span>}
      </button>)}
      <div className="tabs-spacer" />
      {report && <a className="export-link" href={`/api/audits/${audit.id}/export?format=html`}>
        <Icon name="download" size={15} />
        Export report
      </a>}
    </div>
    {tab === 'Overview' && <div className="overview-grid">
      <div className="main-column">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>
                Prioritize the next review
              </h2>
              <p>
                Signals grounded in your source snapshot.
              </p>
            </div>
            <button className="text-button" onClick={() => setTab('Findings')}>
              View all
              <Icon name="arrow" size={14} />
            </button>
          </div>
          {findings.length ? findingTable(findings.slice(0, 5)) : <EmptyState
            title={active ? 'The investigation is in progress' : 'No candidates in the analyzed scope'}
          >
            <p>
              {active ? 'Scanner and workflow events will appear as the worker progresses.' : 'This is not proof that the project is secure. Check what was actually analyzed.'}
            </p>
          </EmptyState>}
        </section>
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>
                Investigation activity
              </h2>
              <p>
                Observable steps, not hidden model reasoning.
              </p>
            </div>
            <Badge>
              LANGGRAPH
            </Badge>
          </div>
          <ol className="timeline">
            {events.slice(-5).map((event) => <li key={event.id}>
              <span className="timeline-dot">
                <Icon name="check" size={11} />
              </span>
              <div>
                <strong>
                  {event.stage.replaceAll('_', ' ')}
                </strong>
                <p>
                  {event.message}
                </p>
              </div>
              <time>
                {utcDate(event.at).split(',').at(-1)}
              </time>
            </li>)}
          </ol>
        </section>
      </div>
      <aside className="right-column">
        <section className="panel trust-panel">
          <div className="panel-header">
            <h2>
              Trust &amp; coverage
            </h2>
            <Icon name="shield" />
          </div>
          <div className="trust-summary">
            <span className="trust-icon">
              <Icon name="shield" size={24} />
            </span>
            <h3>
              Evidence, not a score.
            </h3>
            <p>
              No invented safety percentage. Every conclusion has a source and a review status.
            </p>
          </div>
          <div className="detail-row">
            <span>
              Model inference
            </span>
            <Badge>
              {report?.aiMode === 'ollama' ? 'Local Ollama' : 'Disabled'}
            </Badge>
          </div>
          <div className="detail-row">
            <span>
              Target execution
            </span>
            <strong>
              Never
            </strong>
          </div>
          <div className="detail-row">
            <span>
              Automatic remediation
            </span>
            <strong>
              Off
            </strong>
          </div>
          <div className="detail-row">
            <span>
              Remote tracing
            </span>
            <strong>
              Off
            </strong>
          </div>
          <Link href="/methodology" className="method-link">
            Understand the methodology
            <Icon name="arrow" size={14} />
          </Link>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>
              Scanner coverage
            </h2>
          </div>
          <div className="scanner-mini">
            {report?.scanners.map((scanner) => <div key={scanner.id}>
              <span>
                <span className={scanner.status === 'completed' ? 'live-dot' : 'offline-dot'} />
                {scanner.name}
              </span>
              <small>
                {scanner.status}
              </small>
            </div>) ?? <p className="muted">
                Waiting for scanner results.
              </p>}
          </div>
        </section>
        <div className="scope-note">
          <Icon name="info" size={16} />
          <p>
            A static review is not a pentest or certification. Unknowns are part of the result.
          </p>
        </div>
      </aside>
    </div>}
    {tab === 'Findings' && <section className="panel">
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
          <option value="all">
            All severities
          </option>
          {['critical', 'high', 'medium', 'low', 'info'].map((level) => <option key={level}>
            {level}
          </option>)}
        </select>
        <Badge>
          {visible.length}
          {' '}results
        </Badge>
      </div>
      {visible.length ? findingTable(visible) : <EmptyState title="No matching findings">
        <p>
          Try another filter. Absence of findings is not an assurance of safety.
        </p>
      </EmptyState>}
    </section>}
    {tab === 'Dependencies' && <section className="panel">
      <div className="panel-header">
        <div>
          <h2>
            Dependency inventory
          </h2>
          <p>
            Declared package ranges, not resolved installed versions.
          </p>
        </div>
        <Badge tone="medium">
          VULNERABILITY MATCHING NOT RUN
        </Badge>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>
                Package
              </th>
              <th>
                Requested version
              </th>
              <th>
                Scope
              </th>
              <th>
                Manifest
              </th>
            </tr>
          </thead>
          <tbody>
            {report?.dependencies.map((dependency) => <tr key={`${dependency.manifest}:${dependency.scope}:${dependency.name}`}>
              <td className="strong mono">
                {dependency.name}
              </td>
              <td className="mono">
                {dependency.requestedVersion}
              </td>
              <td>
                {dependency.scope}
              </td>
              <td className="mono small">
                {dependency.manifest}
              </td>
            </tr>)}
          </tbody>
        </table>
      </div>
      <div className="panel-footer">
        OSV/Trivy integration, lockfile resolution, advisory freshness and reachability are explicitly outside this starter&apos;s implemented coverage.
      </div>
    </section>}
    {tab === 'Coverage' && <div className="coverage-grid">
      <section className="panel">
        <div className="panel-header">
          <h2>
            What actually ran
          </h2>
        </div>
        {report?.scanners.map((scanner) => <div className="coverage-row" key={scanner.id}>
          <div className="row spread">
            <strong>
              {scanner.name}
            </strong>
            <Badge tone={scanner.status === 'completed' ? 'success' : 'neutral'}>
              {scanner.status}
            </Badge>
          </div>
          <p>
            {scanner.detail}
          </p>
          <span className="small muted">
            {scanner.findings}
            {' '}findings ·
            {' '}{scanner.durationMs}
            {' '}ms
            {' '}{scanner.version ? ` · v${scanner.version}` : ' · binary version not recorded'}
          </span>
        </div>)}
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>
            Boundaries &amp; exclusions
          </h2>
        </div>
        <div className="panel-body">
          <h3 className="section-label">
            Skipped scope
          </h3>
          {Object.entries(report?.skipped ?? {}).map(([reason, count]) => <div className="detail-row" key={reason}>
            <span>
              {reason.replaceAll('-', ' ')}
            </span>
            <strong>
              {count}
            </strong>
          </div>)}
          <h3 className="section-label">
            Limitations
          </h3>
          <ul className="limitations">
            {report?.limitations.map((limitation) => <li key={limitation}>
              {limitation}
            </li>)}
          </ul>
        </div>
      </section>
    </div>}
    {tab === 'Workflow' && <section className="panel">
      <div className="panel-header">
        <div>
          <h2>
            Audit graph
          </h2>
          <p>
            Persistent checkpoints, parallel scanners, bounded investigation, human publication review.
          </p>
        </div>
        <Badge>
          ONE THREAD PER AUDIT
        </Badge>
      </div>
      <div className="workflow">
        <div className="graph-node done">
          <Icon name="folder" />
          Capture bounded snapshot
        </div>
        <div className="graph-connector">
          ↓
        </div>
        <div className="graph-parallel">
          {['patterns', 'semgrep', 'gitleaks', 'inventory'].map((stage) => <div
            key={stage}
            className={`graph-node ${events.some((event) => event.stage === stage) ? 'done' : ''}`}
          >
            <Icon name="scan" />
            {stage}
          </div>)}
        </div>
        <div className="graph-connector">
          ↓
        </div>
        <div className="graph-node">
          Normalize &amp; prioritize candidates
        </div>
        <div className="graph-connector">
          ↓
        </div>
        <div className="graph-node loop">
          <Icon name="branch" />
          Read → assess → request context
          {' '}<span>
            ≤ 2 rounds / finding · ≤ 12 findings
          </span>
        </div>
        <div className="graph-connector">
          ↓
        </div>
        <div className={`graph-node ${audit.status === 'awaiting_review' ? 'waiting' : ''}`}>
          <Icon name="lock" />
          Human publication review
          {' '}<span>
            interrupt() → Command(resume)
          </span>
        </div>
        <div className="graph-connector">
          ↓
        </div>
        <div className="graph-node">
          Publish with unresolved findings intact
        </div>
      </div>
    </section>}
    {audit.status === 'awaiting_review' && <section className="publication-panel">
      <div>
        <div className="eyebrow">
          HUMAN-IN-THE-LOOP
        </div>
        <h2>
          Ready for your review.
        </h2>
        <p>
          Review findings individually, then acknowledge publication. This does not mark unresolved findings as confirmed.
        </p>
      </div>
      <div className="publication-form">
        <label htmlFor="publication-note">
          Publication review note
        </label>
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
          Publish reviewed report
          <Icon name="arrow" size={16} />
        </button>
      </div>
    </section>}
    <footer className="audit-footer">
      <span>
        <Icon name="lock" size={13} />
        Evidence stays in local storage. Redaction is best effort.
      </span>
      <div className="row gap">
        {report && <>
          <a href={`/api/audits/${audit.id}/export?format=json`}>
            JSON
          </a>
          <a href={`/api/audits/${audit.id}/export?format=md`}>
            Markdown
          </a>
          <a href={`/api/audits/${audit.id}/export?format=sarif`}>
            SARIF
          </a>
        </>}
        {['queued', 'running', 'awaiting_review'].includes(audit.status) && <button className="text-button danger-text" onClick={() => action('cancel')} disabled={pending}>
          Cancel audit
        </button>}
      </div>
    </footer>
    {selected && <FindingDetails
      finding={selected}
      auditId={audit.id}
      reviewable={reviewable}
      close={() => setSelected(null)}
      refresh={refresh}
    />}
  </>;
}
