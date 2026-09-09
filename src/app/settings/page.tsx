import { configuration } from '../../server/config.ts';
import { Badge } from '../../components/ui.tsx';
export const dynamic = 'force-dynamic';
export default function SettingsPage() {
  const config = configuration();
  return <>
    <div className="page-heading">
      <div>
        <div className="eyebrow">
          NO CLOUD ACCOUNT REQUIRED
        </div>
        <h1>
          Local settings
        </h1>
        <p className="subtitle">
          Configuration is explicit and server-side. The UI cannot change executable paths or model hosts.
        </p>
      </div>
    </div>
    <div className="coverage-grid">
      <section className="panel">
        <div className="panel-header">
          <h2>
            Model &amp; privacy
          </h2>
          <Badge tone="success">
            LOCAL FIRST
          </Badge>
        </div>
        <div className="panel-body">
          <div className="detail-row">
            <span>
              Inference mode
            </span>
            <strong>
              {config.aiMode}
            </strong>
          </div>
          <div className="detail-row">
            <span>
              Model
            </span>
            <strong>
              {config.model || 'Not configured'}
            </strong>
          </div>
          <div className="detail-row">
            <span>
              Model endpoint
            </span>
            <code>
              127.0.0.1:11434
            </code>
          </div>
          <div className="detail-row">
            <span>
              Remote tracing
            </span>
            <strong>
              Disabled by worker
            </strong>
          </div>
          <p className="small muted">
            Download a suitable local model separately. Set OLLAMA_NO_CLOUD=1 on the Ollama server and enforce egress controls for strict offline use.
          </p>
          <pre className="command">
            TRACEWARD_AI=ollama
            <br />
            OLLAMA_MODEL=your-downloaded-model
          </pre>
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>
            Scanner integrations
          </h2>
        </div>
        <div className="panel-body">
          <div className="detail-row">
            <span>
              Built-in review patterns
            </span>
            <Badge tone="success">
              Enabled
            </Badge>
          </div>
          <div className="detail-row">
            <span>
              Semgrep
            </span>
            <Badge>
              {config.semgrep ? 'Opted in' : 'Disabled'}
            </Badge>
          </div>
          <div className="detail-row">
            <span>
              Gitleaks
            </span>
            <Badge>
              {config.gitleaks ? 'Opted in' : 'Disabled'}
            </Badge>
          </div>
          <div className="detail-row">
            <span>
              OSV / Trivy
            </span>
            <Badge>
              Planned
            </Badge>
          </div>
          <p className="small muted">
            Install trusted binaries yourself. The application never downloads executables or rules from a scanned repository.
          </p>
          <pre className="command">
            TRACEWARD_SEMGREP=true
            <br />
            TRACEWARD_GITLEAKS=true
          </pre>
        </div>
      </section>
    </div>
    <section className="panel prose">
      <h2>
        Operational boundaries
      </h2>
      <p>
        Set values in
        {' '}<code>
          .env.local
        </code>
        {' '}and restart the worker. Use a single worker on a local filesystem. Data is stored under
        {' '}<code>
          {config.dataDirectory}
        </code>
        . Do not use a shared network filesystem or expose this preview as a public SaaS.
      </p>
      <p>
        To delete local reports, stop both processes and remove only the configured data directory. This release does not provide a UI cleanup action or retention scheduler.
      </p>
    </section>
  </>;
}
