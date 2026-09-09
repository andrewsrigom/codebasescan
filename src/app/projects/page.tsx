import { store } from '../../server/context.ts';
import { Icon } from '../../components/icon.tsx';
import { NewAudit } from '../../components/new-audit.tsx';
import { Badge } from '../../components/ui.tsx';
export const dynamic = 'force-dynamic';
export default function ProjectsPage() {
  const projects = store().projects();
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">EXPLICITLY AUTHORIZED SCOPE</div>
          <h1>Projects</h1>
          <p className="subtitle">The browser cannot browse arbitrary paths on your machine.</p>
        </div>
        <NewAudit projects={projects.map(({ id, name }) => ({ id, name }))} />
      </div>
      <div className="project-grid">
        {projects.map((project) => (
          <section className="panel project-card" key={project.id}>
            <div className="row spread">
              <span className="project-icon">
                <Icon name="folder" size={26} />
              </span>
              <Badge>LOCAL</Badge>
            </div>
            <h2>{project.name}</h2>
            <p className="mono small">{project.root}</p>
            <div className="detail-row">
              <span>Access</span>
              <strong>Read-only snapshot</strong>
            </div>
          </section>
        ))}
      </div>
      <section className="panel">
        <div className="panel-body">
          <h2>Register a repository</h2>
          <p>
            Registration happens through the CLI, under your OS account. Never register a project
            you are not authorized to inspect.
          </p>
          <pre className="command">npm run cli -- register /absolute/path/to/project</pre>
          <p className="small muted">
            Home directories, filesystem roots and audit storage overlap are rejected. To audit
            Traceward itself, place TRACEWARD_DATA_DIR outside this repository.
          </p>
        </div>
      </section>
    </>
  );
}
