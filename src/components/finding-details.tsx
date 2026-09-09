'use client';
import { useEffect, useRef, useState } from 'react';
import type { Disposition, Finding } from '../domain/types.ts';
import { Icon } from './icon.tsx';
import { Badge, SeverityBadge } from './ui.tsx';
import { mutate } from './new-audit.tsx';
export function FindingDetails({ finding, auditId, reviewable, close, refresh }: {
  finding: Finding;
  auditId: string;
  reviewable: boolean;
  close: () => void;
  refresh: () => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [disposition, setDisposition] = useState<Disposition>(finding.disposition);
  const [note, setNote] = useState(finding.review?.note ?? '');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  useEffect(() => { dialog.current?.showModal(); }, []);
  async function save() {
    setPending(true);
    setError('');
    try {
      await mutate(`/api/audits/${auditId}`, { action: 'review', findingId: finding.id, disposition, note });
      await refresh();
      close();
    }
    catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not save the review.');
    }
    finally {
      setPending(false);
    }
  }
  return <dialog ref={dialog} className="finding-dialog" onClose={close} aria-labelledby="finding-title">
    <div className="drawer-header">
      <div className="eyebrow">
        FINDING /
        {finding.ruleId}
      </div>
      <button className="icon-button" aria-label="Close finding" onClick={close}>
        <Icon name="close" />
      </button>
    </div>
    <div className="drawer-body">
      <div className="row gap">
        <SeverityBadge severity={finding.severity} />
        <Badge>
          {finding.source}
        </Badge>
        <Badge tone="neutral">
          {finding.disposition.replaceAll('_', ' ')}
        </Badge>
      </div>
      <h2 id="finding-title" className="finding-title">
        {finding.title}
      </h2>
      <p>
        {finding.description}
      </p>
      <div className="notice">
        <Icon name="info" />
        <span>
          Scanner detection and model assessment are not proof of exploitability. A human decision is tracked separately.
        </span>
      </div>
      <section>
        <h3 className="section-label">
          Evidence
        </h3>
        {finding.evidence.map((evidence) => <div className="evidence" key={evidence.id}>
          <div className="code-header">
            <Icon name="code" size={15} />
            <span>
              {evidence.file}
              :
              {' '}{evidence.startLine}
              {' '}–
              {' '}{evidence.endLine}
            </span>
          </div>
          <pre className="code-block">
            {evidence.excerpt}
          </pre>
          <p className="small">
            {evidence.observation}
          </p>
          <span className="digest">
            SHA-256
            {' '}{evidence.fileDigest.slice(0, 16)}
            {' '}…
          </span>
        </div>)}
      </section>
      {finding.analysis && <section>
        <h3 className="section-label">
          Contextual assessment
          <Badge>
            {finding.analysis.kind}
          </Badge>
        </h3>
        <p>
          {finding.analysis.explanation}
        </p>
        <div className="small muted">
          {finding.analysis.inspectedFiles.length}
          {' '}file(s) inspected ·
          {' '}{finding.analysis.rounds}
          {' '}round(s) ·
          {' '}{finding.analysis.assessment.replaceAll('_', ' ')}
        </div>
        <ul className="limitations">
          {finding.analysis.limitations.map((limitation) => <li key={limitation}>
            {limitation}
          </li>)}
        </ul>
      </section>}
      <section>
        <h3 className="section-label">
          Recommended next step
        </h3>
        <p>
          {finding.remediation}
        </p>
        <div className="row gap">
          {finding.cwe.map((cwe) => <Badge key={cwe}>
            {cwe}
          </Badge>)}
        </div>
      </section>
      <section className="review-section">
        <h3 className="section-label">
          Human review
        </h3>
        <label htmlFor="review-disposition">
          Disposition
        </label>
        <select
          id="review-disposition"
          value={disposition}
          disabled={!reviewable}
          onChange={(event) => setDisposition(event.target.value as Disposition)}
        >
          <option value="needs_review">
            Needs review
          </option>
          <option value="confirmed">
            Confirmed by reviewer
          </option>
          <option value="false_positive">
            False positive
          </option>
          <option value="accepted_risk">
            Accepted risk
          </option>
        </select>
        <label htmlFor="review-note">
          Evidence and rationale
        </label>
        <textarea
          id="review-note"
          rows={4}
          value={note}
          maxLength={2000}
          onChange={(event) => setNote(event.target.value)}
          placeholder="Describe what you verified, including supporting code or test evidence."
          disabled={!reviewable}
        />
        <p className="small muted">
          This is an analyst assertion, not an automatically verified exploit. At least 12 characters are required.
        </p>
        <button
          className="button primary"
          disabled={!reviewable || pending || note.trim().length < 12}
          onClick={save}
        >
          Save review
        </button>
        {error && <p className="error-text" role="alert">
          {error}
        </p>}
      </section>
    </div>
  </dialog>;
}
