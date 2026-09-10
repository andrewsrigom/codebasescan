import type { RemediationPlan } from '../domain/remediation.ts';
import { Badge, EmptyState, SeverityBadge } from './audit-primitives.tsx';

const kindLabel = (kind: RemediationPlan['tasks'][number]['kind']) => kind.replaceAll('_', ' ');

export function RemediationQueue({
  plan,
  onSelectFinding,
}: {
  plan: RemediationPlan | null;
  onSelectFinding: (findingId: string) => void;
}) {
  if (!plan)
    return (
      <section
        className="panel"
        id="audit-panel-remediation"
        role="tabpanel"
        aria-labelledby="audit-tab-remediation"
      >
        <EmptyState title="Remediation plan not generated">
          <p>Wait for the deterministic audit report to complete.</p>
        </EmptyState>
      </section>
    );

  return (
    <section
      className="panel remediation-queue"
      id="audit-panel-remediation"
      role="tabpanel"
      aria-labelledby="audit-tab-remediation"
    >
      <div className="panel-header">
        <div>
          <h2>Remediation queue</h2>
          <p>Machine-readable work items for Codex or another authorized agent.</p>
        </div>
        <Badge>PLAN V{plan.schemaVersion}</Badge>
      </div>
      <div className="stat-grid remediation-summary">
        <div className="stat-card">
          <div className="stat-label">Tasks</div>
          <div className="stat-number">{plan.summary.tasks}</div>
          <div className="stat-foot">Grouped from findings and controls</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Ready for analysis</div>
          <div className="stat-number">{plan.summary.ready}</div>
          <div className="stat-foot">Plan only; no change is authorized</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Dependency tasks</div>
          <div className="stat-number">
            {plan.summary.byKind.upgrade_dependency +
              plan.tasks.filter(
                (task) => task.kind === 'investigate_finding' && task.target.type === 'dependency',
              ).length}
          </div>
          <div className="stat-foot">Upgrade or branch investigation</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Blocked</div>
          <div className="stat-number">{plan.summary.blocked}</div>
          <div className="stat-foot">Needs coverage or external evidence</div>
        </div>
      </div>

      <div className="remediation-task-list">
        {plan.tasks.map((task) => (
          <article className="remediation-task" key={task.id}>
            <header>
              <div>
                <span className="mono remediation-task-id">{task.id}</span>
                <h3>{task.title}</h3>
                <p>{task.rationale}</p>
              </div>
              <div className="remediation-task-badges">
                <SeverityBadge severity={task.severity} />
                <Badge tone={task.status === 'ready' ? 'success' : 'medium'}>
                  {task.status.replaceAll('_', ' ')}
                </Badge>
                <Badge>{kindLabel(task.kind)}</Badge>
              </div>
            </header>

            <div className="remediation-task-meta">
              {task.target.package && <code>{task.target.package}</code>}
              {task.target.currentVersion && <span>current {task.target.currentVersion}</span>}
              {task.target.fixCandidate && <span>candidate {task.target.fixCandidate}</span>}
              <span>{task.findings.length} linked findings</span>
              <span>{task.acceptanceChecks.length} checks</span>
            </div>

            <details>
              <summary>Instructions, evidence, and acceptance checks</summary>
              <div className="remediation-task-details">
                <div>
                  <h4>Instructions</h4>
                  <ol>
                    {task.instructions.map((instruction) => (
                      <li key={instruction}>{instruction}</li>
                    ))}
                  </ol>
                </div>
                <div>
                  <h4>Acceptance</h4>
                  <ul>
                    {task.acceptanceChecks.map((item) => (
                      <li key={item.id}>{item.description}</li>
                    ))}
                  </ul>
                </div>
                {task.findings.length > 0 && (
                  <div>
                    <h4>Findings</h4>
                    <div className="remediation-finding-links">
                      {task.findings.map((finding) => (
                        <button
                          key={finding.id}
                          type="button"
                          onClick={() => onSelectFinding(finding.id)}
                        >
                          {finding.ruleId}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                {task.uncertainties.length > 0 && (
                  <div>
                    <h4>Uncertainties</h4>
                    <ul>
                      {task.uncertainties.map((uncertainty) => (
                        <li key={uncertainty}>{uncertainty}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </details>
          </article>
        ))}
      </div>
      <div className="panel-footer">
        This queue is analysis input. It does not authorize commands, edits, network access,
        suppression, or publication.
      </div>
    </section>
  );
}
