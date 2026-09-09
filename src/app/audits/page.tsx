import Link from 'next/link';
import { store } from '../../server/context.ts';
import { NewAudit } from '../../components/new-audit.tsx';
import { EmptyState, StatusBadge, utcDate } from '../../components/ui.tsx';
import { Icon } from '../../components/icon.tsx';
export const dynamic = 'force-dynamic';
export default function AuditHistoryPage() {
  const database = store();
  const audits = database.audits();
  return <>
    <div className="page-heading">
      <div>
        <div className="eyebrow">
          YOUR REVIEW TRAIL
        </div>
        <h1>
          Audit history
        </h1>
        <p className="subtitle">
          A bounded source snapshot and a review trail for every run.
        </p>
      </div>
      <NewAudit projects={database.projects().map(({ id, name }) => ({ id, name }))} />
    </div>
    <section className="panel">
      {audits.length ? <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>
                Project
              </th>
              <th>
                Audit
              </th>
              <th>
                Created / UTC
              </th>
              <th>
                Findings
              </th>
              <th>
                Status
              </th>
              <th>
                <span className="sr-only">
                  Open
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            {audits.map((audit) => <tr key={audit.id}>
              <td>
                <Link className="strong" href={`/audits/${audit.id}`}>
                  {audit.projectName}
                </Link>
              </td>
              <td className="mono small">
                {audit.id.slice(0, 8)}
              </td>
              <td>
                {utcDate(audit.createdAt)}
              </td>
              <td>
                {audit.report?.findings.length ?? '—'}
              </td>
              <td>
                <StatusBadge status={audit.status} />
              </td>
              <td>
                <Link href={`/audits/${audit.id}`} aria-label={`Open audit ${audit.id.slice(0, 8)}`}>
                  <Icon name="arrow" />
                </Link>
              </td>
            </tr>)}
          </tbody>
        </table>
      </div> : <EmptyState title="No audits yet">
        <p>
          Run the demo or register a project to start.
        </p>
      </EmptyState>}
      <div className="panel-footer">
        Latest 100 audits. Historical absence of a finding is not proof of remediation; cross-scan resolution is intentionally not inferred.
      </div>
    </section>
  </>;
}
