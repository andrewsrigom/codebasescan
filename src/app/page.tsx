import { store } from '../server/context.ts';
import { AuditWorkspace } from '../components/audit-workspace.tsx';
import { NewAudit } from '../components/new-audit.tsx';
import { EmptyState } from '../components/ui.tsx';
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';
export default function HomePage() {
  const database = store();
  const latest = database.audits()[0];
  const projects = database.projects().map(({ id, name }) => ({ id, name }));
  if (!latest)
    return <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            LOCAL-FIRST SECURITY REVIEW
          </div>
          <h1>
            Security, with evidence.
          </h1>
          <p className="subtitle">
            A workbench for understanding risk, not inventing confidence.
          </p>
        </div>
        <NewAudit projects={projects} />
      </div>
      <section className="panel">
        <EmptyState title="Your first audit starts here">
          <p>
            Load the small, deliberately review-worthy demo repository:
          </p>
          <pre className="command">
            npm run demo
          </pre>
          <p>
            Or register your own project, start the worker, and queue an audit.
          </p>
          <pre className="command">
            npm run cli -- register /path/to/project
            <br />
            npm run worker
          </pre>
        </EmptyState>
      </section>
    </>;
  return <AuditWorkspace
    key={latest.id}
    initialAudit={latest}
    initialEvents={database.events(latest.id)}
    initialWorkerOnline={database.workerOnline()}
    projects={projects}
  />;
}
