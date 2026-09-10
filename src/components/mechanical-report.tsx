import type {
  ApiContractAnalysis,
  CodeQualityAnalysis,
  MechanicalAnalysis,
  SupplyChainAnalysis,
  TestEvidenceAnalysis,
} from '../domain/types.ts';
import { Badge, EmptyState } from './ui.tsx';

const supplyLabels: Record<keyof SupplyChainAnalysis['issueCounts'], string> = {
  dangerousLifecycleScripts: 'Dangerous lifecycle scripts',
  unsafeDependencySpecs: 'Unsafe dependency sources',
  weakLockfileIntegrity: 'Weak or missing integrity',
  insecureLockfileUrls: 'Plaintext lockfile URLs',
  unexpectedLockfileHosts: 'Non-default package hosts',
  manifestLockMismatches: 'Manifest/lock mismatches',
};

export function MechanicalReportPanel({
  analysis,
  supplyChain,
  quality,
  testEvidence,
  apiContract,
}: {
  analysis?: MechanicalAnalysis;
  supplyChain?: SupplyChainAnalysis;
  quality?: CodeQualityAnalysis;
  testEvidence?: TestEvidenceAnalysis;
  apiContract?: ApiContractAnalysis;
}) {
  const architecture = analysis?.architecture;
  const duplication = analysis?.duplication;
  const cycleCount = architecture?.cycleCount ?? architecture?.cycles.length;
  const orphanCount = architecture?.orphanCount ?? architecture?.orphanCandidates.length;
  const architectureHotspotCount = architecture?.hotspotCount ?? architecture?.hotspots.length;
  const qualityHotspotCount = quality?.hotspotCount ?? quality?.hotspots.length;
  const unusedFileCount = quality?.deadCode
    ? (quality.deadCode.unusedFileCount ?? quality.deadCode.unusedFiles.length)
    : undefined;
  const unusedDependencyCount = quality?.deadCode
    ? (quality.deadCode.unusedDependencyCount ?? quality.deadCode.unusedDependencies.length)
    : undefined;
  const unusedSymbolCount = quality?.deadCode
    ? (quality.deadCode.unusedExportCount ?? quality.deadCode.unusedExports.length) +
      (quality.deadCode.unusedTypeCount ?? quality.deadCode.unusedTypes.length)
    : undefined;
  const targetsWithoutRelatedTests =
    testEvidence?.targets.filter((target) => target.status === 'not-observed') ?? [];
  const declaredOnlyOperations =
    apiContract?.declaredOperations.filter((operation) => operation.status === 'declared-only') ??
    [];
  const sourceOnlyOperations =
    apiContract?.sourceOperations.filter((operation) => operation.status === 'source-only') ?? [];
  const complete = Boolean(
    architecture &&
    !architecture.truncated &&
    duplication &&
    !duplication.truncated &&
    supplyChain &&
    !supplyChain.truncated &&
    quality?.deadCode &&
    !quality.truncated &&
    testEvidence?.status === 'complete' &&
    !testEvidence.truncated &&
    apiContract?.status === 'complete' &&
    !apiContract.truncated,
  );
  return (
    <section
      className="panel"
      id="audit-panel-source-analysis"
      role="tabpanel"
      aria-labelledby="audit-tab-source-analysis"
    >
      <div className="panel-header">
        <div>
          <h2>Source analysis</h2>
          <p>Supply chain, API contracts, code quality, tests, structure, and duplication.</p>
        </div>
        <Badge tone={complete ? 'success' : 'medium'}>
          {complete ? 'COMPLETE DATA' : 'PARTIAL DATA'}
        </Badge>
      </div>
      {!architecture &&
      !duplication &&
      !supplyChain &&
      !quality &&
      !testEvidence &&
      !apiContract ? (
        <EmptyState title="Source analysis unavailable">
          <p>Check scanner status in Coverage. No clean result is implied.</p>
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
                <div className="stat-number">{cycleCount ?? '—'}</div>
                <div className="stat-foot">{orphanCount ?? '—'} orphan candidates</div>
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

          {supplyChain && (
            <>
              <div className="panel-header">
                <div>
                  <h2>Supply-chain integrity</h2>
                  <p>Manifest and lockfile declarations only. No package was installed.</p>
                </div>
                <Badge>{supplyChain.lockEntries} lock entries</Badge>
              </div>
              <div className="panel-body">
                <div className="stat-grid">
                  <div className="stat-card">
                    <div className="stat-label">Manifests</div>
                    <div className="stat-number">{supplyChain.manifests}</div>
                    <div className="stat-foot">{supplyChain.lockfiles} lockfiles</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-label">Dependency specs</div>
                    <div className="stat-number">{supplyChain.dependencySpecs}</div>
                    <div className="stat-foot">
                      {supplyChain.lifecycleScripts} lifecycle scripts
                    </div>
                  </div>
                </div>
              </div>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Check</th>
                      <th>Candidates</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(supplyChain.issueCounts).map(([key, count]) => (
                      <tr key={key}>
                        <td>{supplyLabels[key as keyof SupplyChainAnalysis['issueCounts']]}</td>
                        <td>{count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {quality && (
            <>
              <div className="panel-header">
                <div>
                  <h2>Code quality</h2>
                  <p>Bounded TypeScript/JavaScript metrics and isolated dead-code analysis.</p>
                </div>
                <Badge>{qualityHotspotCount} hotspots</Badge>
              </div>
              <div className="panel-body">
                <div className="stat-grid">
                  <div className="stat-card">
                    <div className="stat-label">Functions measured</div>
                    <div className="stat-number">{quality.functionsAnalyzed}</div>
                    <div className="stat-foot">{quality.filesAnalyzed} source files</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-label">Unused files</div>
                    <div className="stat-number">{unusedFileCount ?? '—'}</div>
                    <div className="stat-foot">
                      {unusedDependencyCount ?? '—'} unused dependencies
                    </div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-label">Unused symbols</div>
                    <div className="stat-number">{unusedSymbolCount ?? '—'}</div>
                    <div className="stat-foot">Knip candidates</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-label">Coverage artifacts</div>
                    <div className="stat-number">{quality.coverageArtifacts.length}</div>
                    <div className="stat-foot">Imported, never generated</div>
                  </div>
                </div>
              </div>
              {quality.hotspots.length > 0 && (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Function</th>
                        <th>Location</th>
                        <th>Complexity</th>
                        <th>Lines</th>
                        <th>Parameters</th>
                      </tr>
                    </thead>
                    <tbody>
                      {quality.hotspots.map((hotspot) => (
                        <tr key={`${hotspot.file}:${hotspot.line}:${hotspot.name}`}>
                          <td className="strong mono">{hotspot.name}</td>
                          <td className="mono small">
                            {hotspot.file}:{hotspot.line}
                          </td>
                          <td>{hotspot.complexity}</td>
                          <td>{hotspot.lines}</td>
                          <td>{hotspot.parameters}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {quality.deadCode &&
                (quality.deadCode.unusedFiles.length > 0 ||
                  quality.deadCode.unusedDependencies.length > 0) && (
                  <div className="panel-body">
                    {quality.deadCode.unusedFiles.length > 0 && (
                      <>
                        <h3 className="section-label">Unused file candidates</h3>
                        <ul className="limitations">
                          {quality.deadCode.unusedFiles.map((file) => (
                            <li className="mono" key={file}>
                              {file}
                            </li>
                          ))}
                        </ul>
                      </>
                    )}
                    {quality.deadCode.unusedDependencies.length > 0 && (
                      <>
                        <h3 className="section-label">Unused dependency candidates</h3>
                        <ul className="limitations">
                          {quality.deadCode.unusedDependencies.map((dependency) => (
                            <li className="mono" key={dependency}>
                              {dependency}
                            </li>
                          ))}
                        </ul>
                      </>
                    )}
                  </div>
                )}
              {quality.coverageArtifacts.length > 0 && (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Coverage artifact</th>
                        <th>Lines</th>
                        <th>Statements</th>
                        <th>Functions</th>
                        <th>Branches</th>
                      </tr>
                    </thead>
                    <tbody>
                      {quality.coverageArtifacts.map((artifact) => (
                        <tr key={artifact.file}>
                          <td className="mono small">{artifact.file}</td>
                          <td>{artifact.lines ?? '—'}</td>
                          <td>{artifact.statements ?? '—'}</td>
                          <td>{artifact.functions ?? '—'}</td>
                          <td>{artifact.branches ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {apiContract && (
            <>
              <div className="panel-header">
                <div>
                  <h2>API contract consistency</h2>
                  <p>Captured OpenAPI/Swagger declarations compared with mapped source routes.</p>
                </div>
                <Badge
                  tone={
                    apiContract.summary.declaredOnly + apiContract.summary.sourceOnly
                      ? 'medium'
                      : apiContract.status === 'complete'
                        ? 'success'
                        : 'neutral'
                  }
                >
                  {apiContract.summary.declaredOnly + apiContract.summary.sourceOnly} differences
                </Badge>
              </div>
              <div className="panel-body">
                {apiContract.status === 'unsupported' ? (
                  <p className="small muted">
                    No captured OpenAPI or Swagger specification was found. No clean result is
                    implied.
                  </p>
                ) : (
                  <div className="stat-grid">
                    <div className="stat-card">
                      <div className="stat-label">Declared operations</div>
                      <div className="stat-number">{apiContract.summary.declaredOperations}</div>
                      <div className="stat-foot">
                        {apiContract.summary.declaredOnly} without source match
                      </div>
                    </div>
                    <div className="stat-card">
                      <div className="stat-label">Source operations</div>
                      <div className="stat-number">{apiContract.summary.sourceOperations}</div>
                      <div className="stat-foot">
                        {apiContract.summary.sourceOnly} in-scope differences;{' '}
                        {apiContract.summary.outsideContractScope} outside scope
                      </div>
                    </div>
                    <div className="stat-card">
                      <div className="stat-label">Matched operations</div>
                      <div className="stat-number">{apiContract.summary.matchedOperations}</div>
                      <div className="stat-foot">Method and normalized path</div>
                    </div>
                  </div>
                )}
                <p className="small muted">
                  Differences are documentation consistency candidates, not proof that an endpoint
                  is missing or exposed.
                </p>
              </div>
              {(declaredOnlyOperations.length > 0 || sourceOnlyOperations.length > 0) && (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Difference</th>
                        <th>Operation</th>
                        <th>Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {declaredOnlyOperations.slice(0, 50).map((operation) => (
                        <tr key={operation.id}>
                          <td>Declared only</td>
                          <td className="strong mono">
                            {operation.method} {operation.path}
                          </td>
                          <td className="mono small">
                            {operation.file}:{operation.line}
                          </td>
                        </tr>
                      ))}
                      {sourceOnlyOperations.slice(0, 50).map((operation) => (
                        <tr key={operation.id}>
                          <td>Source only</td>
                          <td className="strong mono">
                            {operation.method} {operation.path}
                          </td>
                          <td className="mono small">
                            {operation.file}:{operation.line}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {testEvidence && (
            <>
              <div className="panel-header">
                <div>
                  <h2>Security-critical test evidence</h2>
                  <p>Import relationships only. Tests were not executed.</p>
                </div>
                <Badge tone={testEvidence.withoutRelatedTests ? 'medium' : 'success'}>
                  {testEvidence.withoutRelatedTests} not observed
                </Badge>
              </div>
              <div className="panel-body">
                <div className="stat-grid">
                  <div className="stat-card">
                    <div className="stat-label">Test files inspected</div>
                    <div className="stat-number">{testEvidence.testFiles}</div>
                    <div className="stat-foot">No execution</div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-label">Critical source files</div>
                    <div className="stat-number">{testEvidence.criticalFiles}</div>
                    <div className="stat-foot">
                      {testEvidence.withRelatedTests} with related imports
                    </div>
                  </div>
                </div>
                <p className="small muted">
                  Not observed means no related captured test import was found. It does not prove
                  that a source file is untested.
                </p>
              </div>
              {targetsWithoutRelatedTests.length > 0 && (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Critical source file</th>
                        <th>Entry points</th>
                        <th>Sensitive facts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {targetsWithoutRelatedTests.slice(0, 100).map((target) => (
                        <tr key={target.file}>
                          <td className="strong mono">{target.file}</td>
                          <td>{target.entrypointIds.length}</td>
                          <td>{target.sensitiveFactKinds.join(', ') || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {architecture && (
            <>
              <div className="panel-header">
                <div>
                  <h2>Coupling hotspots</h2>
                  <p>Files with the most incoming and outgoing local dependencies.</p>
                </div>
                <Badge>
                  {architecture.hotspots.length} of {architectureHotspotCount} shown
                </Badge>
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
                <Badge>
                  {duplication.blocks.length} of {duplication.clones} retained
                </Badge>
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
          {(architecture?.truncated ||
            duplication?.truncated ||
            supplyChain?.truncated ||
            quality?.truncated ||
            testEvidence?.truncated ||
            apiContract?.truncated) && (
            <div className="panel-footer">
              Totals are exact where shown; detailed rows are bounded. Review Coverage for the
              specific scanner limitation.
            </div>
          )}
        </>
      )}
    </section>
  );
}
