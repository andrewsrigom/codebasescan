import type { MechanicalAnalysis } from '../domain/types.ts';
import { Badge, EmptyState } from './ui.tsx';

export function MechanicalReportPanel({ analysis }: { analysis?: MechanicalAnalysis }) {
  const architecture = analysis?.architecture;
  const duplication = analysis?.duplication;
  return (
    <section
      className="panel"
      id="audit-panel-mechanical"
      role="tabpanel"
      aria-labelledby="audit-tab-mechanical"
    >
      <div className="panel-header">
        <div>
          <h2>Mechanical analysis</h2>
          <p>Dependency structure and duplicated code from the bounded source snapshot.</p>
        </div>
        <Badge tone={architecture && duplication ? 'success' : 'medium'}>
          {architecture && duplication ? 'COMPLETE DATA' : 'PARTIAL DATA'}
        </Badge>
      </div>
      {!architecture && !duplication ? (
        <EmptyState title="Mechanical analysis unavailable">
          <p>Check dependency-cruiser and jscpd status in Coverage. No clean result is implied.</p>
        </EmptyState>
      ) : (
        <>
          <div className="panel-body">
            <div className="stat-grid">
              <div className="stat-card">
                <div className="stat-label">Modules mapped</div>
                <div className="stat-number">{architecture?.modules ?? '—'}</div>
                <div className="stat-foot">
                  {architecture?.localDependencies ?? '—'} local dependencies
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Dependency cycles</div>
                <div className="stat-number">{architecture?.cycles.length ?? '—'}</div>
                <div className="stat-foot">
                  {architecture?.orphanCandidates.length ?? '—'} orphan candidates
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Duplicate blocks</div>
                <div className="stat-number">{duplication?.clones ?? '—'}</div>
                <div className="stat-foot">
                  {duplication?.duplicatedLines ?? '—'} duplicated lines
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Duplication</div>
                <div className="stat-number">
                  {duplication ? duplication.percentage.toFixed(2) : '—'}
                  {duplication && <span>percent</span>}
                </div>
                <div className="stat-foot">Maintainability metric, not a security score</div>
              </div>
            </div>
            <p className="small muted">
              Cycles, coupling, orphan modules, and duplicate blocks are review evidence. They are
              not vulnerabilities by themselves.
            </p>
          </div>

          {architecture && (
            <>
              <div className="panel-header">
                <div>
                  <h2>Coupling hotspots</h2>
                  <p>Files with the most incoming and outgoing local dependencies.</p>
                </div>
                <Badge>{architecture.hotspots.length} shown</Badge>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>File</th>
                      <th>Incoming</th>
                      <th>Outgoing</th>
                      <th>Instability</th>
                    </tr>
                  </thead>
                  <tbody>
                    {architecture.hotspots.map((hotspot) => (
                      <tr key={hotspot.file}>
                        <td className="strong mono">{hotspot.file}</td>
                        <td>{hotspot.incoming}</td>
                        <td>{hotspot.outgoing}</td>
                        <td>{hotspot.instability.toFixed(2)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {architecture.cycles.length > 0 && (
                <div className="panel-body">
                  <h3 className="section-label">Dependency cycles</h3>
                  <ul className="limitations">
                    {architecture.cycles.map((cycle) => (
                      <li className="mono" key={cycle.id}>
                        {cycle.files.join(' → ')}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {architecture.orphanCandidates.length > 0 && (
                <div className="panel-body">
                  <h3 className="section-label">Orphan candidates</h3>
                  <ul className="limitations">
                    {architecture.orphanCandidates.map((file) => (
                      <li className="mono" key={file}>
                        {file}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}

          {duplication && (
            <>
              <div className="panel-header">
                <div>
                  <h2>Duplicate blocks</h2>
                  <p>Locations only. Raw duplicated source fragments are discarded.</p>
                </div>
                <Badge>{duplication.blocks.length} retained</Badge>
              </div>
              {duplication.blocks.length ? (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Kind</th>
                        <th>Lines</th>
                        <th>First location</th>
                        <th>Second location</th>
                      </tr>
                    </thead>
                    <tbody>
                      {duplication.blocks.map((block) => (
                        <tr key={block.id}>
                          <td>{block.kind}</td>
                          <td>{block.lines}</td>
                          <td className="mono small">
                            {block.first.file}:{block.first.startLine}-{block.first.endLine}
                          </td>
                          <td className="mono small">
                            {block.second.file}:{block.second.startLine}-{block.second.endLine}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState title="No duplicate blocks retained">
                  <p>The configured minimum is 10 lines and 70 tokens.</p>
                </EmptyState>
              )}
            </>
          )}
          {(architecture?.truncated || duplication?.truncated) && (
            <div className="panel-footer">
              This mechanical report was truncated or filtered. Review Coverage before relying on
              the totals.
            </div>
          )}
        </>
      )}
    </section>
  );
}
