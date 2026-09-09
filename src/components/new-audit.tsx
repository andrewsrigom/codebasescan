'use client';
import { useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { Project, ProjectScopeEstimate } from '../domain/types.ts';
import { Icon } from './icon.tsx';
export async function mutate(url: string, body: unknown): Promise<unknown> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Traceward-Client': 'local-ui' },
    body: JSON.stringify(body),
  });
  const payload = (await response.json()) as {
    error?: string;
  };
  if (!response.ok) throw new Error(payload.error ?? 'The action could not be completed.');
  return payload;
}
export function NewAudit({ projects }: { projects: Pick<Project, 'id' | 'name'>[] }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [selected, setSelected] = useState(projects[0]?.id ?? '');
  const [probeUrl, setProbeUrl] = useState('');
  const [probeApproved, setProbeApproved] = useState(false);
  const [allowPrivateNetwork, setAllowPrivateNetwork] = useState(false);
  const [estimate, setEstimate] = useState<ProjectScopeEstimate | null>(null);
  const [estimating, setEstimating] = useState(false);
  const [approveTruncation, setApproveTruncation] = useState(false);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const estimateRequest = useRef(0);
  const router = useRouter();
  async function loadEstimate(projectId: string) {
    if (!projectId) return;
    const requestId = ++estimateRequest.current;
    setEstimating(true);
    setEstimate(null);
    setApproveTruncation(false);
    setError('');
    try {
      const response = await fetch(`/api/projects/${projectId}/estimate`, { cache: 'no-store' });
      const payload = (await response.json()) as ProjectScopeEstimate & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? 'Could not estimate project scope.');
      if (requestId === estimateRequest.current) setEstimate(payload);
    } catch (cause) {
      if (requestId === estimateRequest.current)
        setError(cause instanceof Error ? cause.message : 'Could not estimate project scope.');
    } finally {
      if (requestId === estimateRequest.current) setEstimating(false);
    }
  }
  async function start() {
    setPending(true);
    setError('');
    try {
      const payload = (await mutate('/api/audits', {
        projectId: selected,
        approveTruncation,
        ...(probeUrl.trim()
          ? {
              httpProbe: {
                url: probeUrl.trim(),
                approved: probeApproved,
                allowPrivateNetwork,
              },
            }
          : {}),
      })) as {
        id: string;
      };
      dialog.current?.close();
      router.push(`/audits/${payload.id}`);
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not start the audit.');
    } finally {
      setPending(false);
    }
  }
  return (
    <>
      <button
        className="button primary"
        onClick={() => {
          dialog.current?.showModal();
          void loadEstimate(selected);
        }}
      >
        <Icon name="plus" size={16} />
        New audit
      </button>
      <dialog className="modal" ref={dialog} aria-labelledby="new-audit-title">
        <div className="modal-head">
          <h2 id="new-audit-title">Start a security review</h2>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={() => dialog.current?.close()}
          >
            <Icon name="close" />
          </button>
        </div>
        <p>Only projects explicitly registered through the local CLI can be scanned.</p>
        {projects.length ? (
          <>
            <label htmlFor="project-select">Project</label>
            <select
              id="project-select"
              value={selected}
              onChange={(event) => {
                setSelected(event.target.value);
                void loadEstimate(event.target.value);
              }}
            >
              {projects.map((project) => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
            <div className="notice">
              <Icon name="lock" />
              <span>
                Read-only snapshot. No package installation, project execution, or automatic fixes.
              </span>
            </div>
            {estimating && (
              <p className="small muted" role="status">
                Estimating supported source scope…
              </p>
            )}
            {estimate && (
              <div className={`notice${estimate.predictedTruncated ? ' danger' : ''}`}>
                <Icon name={estimate.predictedTruncated ? 'alert' : 'check'} />
                <div>
                  <strong>Pre-audit scope estimate</strong>
                  <p>
                    {estimate.supportedFiles} supported files ·{' '}
                    {(estimate.supportedBytes / (1024 * 1024)).toFixed(2)} MiB. Limit:{' '}
                    {estimate.limits.files} files /{' '}
                    {(estimate.limits.totalBytes / (1024 * 1024)).toFixed(0)} MiB.
                  </p>
                  {estimate.limits.lockfileBytes && (
                    <p>
                      Per file: {(estimate.limits.bytesPerFile / 1024).toFixed(0)} KiB source /{' '}
                      {(estimate.limits.lockfileBytes / (1024 * 1024)).toFixed(0)} MiB lockfile.
                    </p>
                  )}
                  {estimate.scopeFiles && (
                    <p>
                      Runtime analysis: {estimate.scopeFiles.runtime}. Secret-only test/example
                      scope: {estimate.scopeFiles.test + estimate.scopeFiles.example}.
                    </p>
                  )}
                  {estimate.predictedTruncated && (
                    <>
                      <p>Partial snapshot expected: {estimate.reasons.join(', ')}.</p>
                      <label className="row gap">
                        <input
                          type="checkbox"
                          checked={approveTruncation}
                          onChange={(event) => setApproveTruncation(event.target.checked)}
                        />
                        I understand this audit will have partial source coverage.
                      </label>
                    </>
                  )}
                </div>
              </div>
            )}
            <label htmlFor="probe-url">Optional HTTP posture target</label>
            <input
              id="probe-url"
              type="url"
              placeholder="http://127.0.0.1:3000/"
              value={probeUrl}
              onChange={(event) => {
                setProbeUrl(event.target.value);
                setProbeApproved(false);
              }}
            />
            {probeUrl.trim() && (
              <div className="panel-body">
                <label className="row gap">
                  <input
                    type="checkbox"
                    checked={probeApproved}
                    onChange={(event) => setProbeApproved(event.target.checked)}
                  />
                  I approve one bounded HEAD/GET request with a synthetic external Origin.
                </label>
                <label className="row gap">
                  <input
                    type="checkbox"
                    checked={allowPrivateNetwork}
                    onChange={(event) => setAllowPrivateNetwork(event.target.checked)}
                  />
                  Allow a private-network target (loopback does not require this).
                </label>
              </div>
            )}
            <button
              className="button primary full"
              disabled={
                pending ||
                estimating ||
                !selected ||
                !estimate ||
                (estimate.predictedTruncated && !approveTruncation) ||
                (Boolean(probeUrl.trim()) && !probeApproved)
              }
              onClick={start}
            >
              {pending ? 'Queuing…' : 'Queue audit'}
              <Icon name="arrow" size={16} />
            </button>
          </>
        ) : (
          <pre className="command">npm run cli -- register /path/to/project</pre>
        )}
        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}
      </dialog>
    </>
  );
}
