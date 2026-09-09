'use client';
import { useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { Project } from '../domain/types.ts';
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
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const router = useRouter();
  async function start() {
    setPending(true);
    setError('');
    try {
      const payload = (await mutate('/api/audits', {
        projectId: selected,
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
      <button className="button primary" onClick={() => dialog.current?.showModal()}>
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
              onChange={(event) => setSelected(event.target.value)}
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
                  I approve one bounded HEAD/GET request to this target.
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
              disabled={pending || !selected || (Boolean(probeUrl.trim()) && !probeApproved)}
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
