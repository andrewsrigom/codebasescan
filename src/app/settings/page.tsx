import { configuration } from '../../server/config.ts';
import { Badge } from '../../components/audit-primitives.tsx';
export const dynamic = 'force-dynamic';
export default function SettingsPage() {
  const config = configuration();
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">LOCAL BY DEFAULT</div>
          <h1>Local settings</h1>
          <p className="subtitle">
            Configuration is explicit and server-side. The UI cannot change executable paths or
            scanner permissions.
          </p>
        </div>
      </div>
      <div className="coverage-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Audit boundaries</h2>
            <Badge tone="success">LOCAL FIRST</Badge>
          </div>
          <div className="panel-body">
            <div className="detail-row">
              <span>Analysis engine</span>
              <strong>Deterministic</strong>
            </div>
            <div className="detail-row">
              <span>Target execution</span>
              <strong>Never</strong>
            </div>
            <div className="detail-row">
              <span>Built-in model calls</span>
              <strong>None</strong>
            </div>
            <div className="detail-row">
              <span>Remote tracing</span>
              <strong>Disabled by worker</strong>
            </div>
            <p className="small muted">
              CodebaseScan does not require an account, API key, or model provider. Exported review
              rules can be used separately by an authorized coding agent.
            </p>
            <pre className="command">
              npx codebasescan audit .
              <br />
              npx codebasescan agent install codex .
            </pre>
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Scanner integrations</h2>
          </div>
          <div className="panel-body">
            <div className="detail-row">
              <span>Built-in review patterns</span>
              <Badge tone="success">Enabled</Badge>
            </div>
            <div className="detail-row">
              <span>Semgrep</span>
              <Badge>{config.semgrep ? 'Opted in' : 'Disabled'}</Badge>
            </div>
            <div className="detail-row">
              <span>Gitleaks</span>
              <Badge>{config.gitleaks ? 'Opted in' : 'Disabled'}</Badge>
            </div>
            <div className="detail-row">
              <span>Local advisory database</span>
              <Badge>{config.osv ? 'Network refresh enabled' : 'Offline only'}</Badge>
            </div>
            <p className="small muted">
              Install trusted binaries yourself. The application never downloads executables or
              rules from a scanned repository. Offline audits use only the local advisory database
              at <code>{config.advisoryDatabasePath}</code>.
            </p>
            <pre className="command">
              CODEBASESCAN_SEMGREP=true
              <br />
              CODEBASESCAN_GITLEAKS=true
              <br />
              CODEBASESCAN_OSV=true
            </pre>
            <p className="small muted">
              Refresh exact package versions manually with{' '}
              <code>npm run cli -- advisories update /path/to/project</code>.
            </p>
            <p className="small muted">
              Verify the complete local setup with <code>npm run cli -- doctor</code>.
            </p>
          </div>
        </section>
      </div>
      <section className="panel prose">
        <h2>Operational boundaries</h2>
        <p>
          Set values in <code>.env.local</code> and restart the worker. Use a single worker on a
          local filesystem. Data is stored under <code>{config.dataDirectory}</code>. Do not use a
          shared network filesystem or expose this local instance as a public SaaS.
        </p>
        <p>
          To delete local reports, stop both processes and remove only the configured data
          directory. This release does not provide a UI cleanup action or retention scheduler.
        </p>
      </section>
    </>
  );
}
