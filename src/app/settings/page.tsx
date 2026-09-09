import { configuration } from '../../server/config.ts';
import { Badge } from '../../components/ui.tsx';
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
            model hosts.
          </p>
        </div>
      </div>
      <div className="coverage-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Model &amp; privacy</h2>
            <Badge tone={config.aiMode === 'openai' ? 'medium' : 'success'}>
              {config.aiMode === 'openai' ? 'CLOUD OPT-IN' : 'LOCAL FIRST'}
            </Badge>
          </div>
          <div className="panel-body">
            <div className="detail-row">
              <span>Inference mode</span>
              <strong>{config.aiMode}</strong>
            </div>
            <div className="detail-row">
              <span>Model</span>
              <strong>{config.model || 'Not configured'}</strong>
            </div>
            <div className="detail-row">
              <span>Model endpoint</span>
              <code>
                {config.aiMode === 'openai' ? 'api.openai.com/v1/responses' : '127.0.0.1:11434'}
              </code>
            </div>
            <div className="detail-row">
              <span>Remote tracing</span>
              <strong>Disabled by worker</strong>
            </div>
            <p className="small muted">
              OpenAI is disabled unless TRACEWARD_AI=openai. Cloud mode sends only bounded,
              relevant, redacted context with store=false. Use OS egress controls when strict
              offline operation is required.
            </p>
            <pre className="command">
              TRACEWARD_AI=ollama
              <br />
              OLLAMA_MODEL=your-downloaded-model
              <br /># or TRACEWARD_AI=openai with OPENAI_MODEL and OPENAI_API_KEY
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
              <span>OSV / Trivy</span>
              <Badge>{config.osv ? 'OSV opted in' : 'OSV disabled'}</Badge>
            </div>
            <p className="small muted">
              Install trusted binaries yourself. The application never downloads executables or
              rules from a scanned repository.
            </p>
            <pre className="command">
              TRACEWARD_SEMGREP=true
              <br />
              TRACEWARD_GITLEAKS=true
              <br />
              TRACEWARD_OSV=true
            </pre>
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
