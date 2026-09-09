'use client';
import { useEffect, useRef, useState } from 'react';
import type { Disposition, Finding } from '../domain/types.ts';
import { Icon } from './icon.tsx';
import { Badge, SeverityBadge } from './ui.tsx';
import { mutate } from './new-audit.tsx';
export function FindingDetails({
  finding,
  auditId,
  reviewable,
  close,
  refresh,
}: {
  finding: Finding;
  auditId: string;
  reviewable: boolean;
  close: () => void;
  refresh: () => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [disposition, setDisposition] = useState<Disposition>(finding.disposition);
  const [note, setNote] = useState(finding.review?.note ?? '');
  const [suppressionReason, setSuppressionReason] = useState(finding.suppression?.reason ?? '');
  const [suppressionExpiry, setSuppressionExpiry] = useState(
    finding.suppression?.expiresAt?.slice(0, 10) ?? '',
  );
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  async function save() {
    setPending(true);
    setError('');
    try {
      await mutate(`/api/audits/${auditId}`, {
        action: 'review',
        findingId: finding.id,
        disposition,
        note,
      });
      await refresh();
      close();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not save the review.');
    } finally {
      setPending(false);
    }
  }
  async function updateSuppression(remove = false) {
    setPending(true);
    setError('');
    try {
      await mutate(`/api/audits/${auditId}`, {
        action: remove ? 'remove-suppression' : 'suppress',
        findingId: finding.id,
        ...(!remove
          ? {
              reason: suppressionReason,
              ...(suppressionExpiry ? { expiresAt: `${suppressionExpiry}T23:59:59.999Z` } : {}),
            }
          : {}),
      });
      await refresh();
      close();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not update the exception.');
    } finally {
      setPending(false);
    }
  }
  return (
    <dialog ref={dialog} className="finding-dialog" onClose={close} aria-labelledby="finding-title">
      <div className="drawer-header">
        <div className="eyebrow">FINDING /{finding.ruleId}</div>
        <button className="icon-button" aria-label="Close finding" onClick={close}>
          <Icon name="close" />
        </button>
      </div>
      <div className="drawer-body">
        <div className="row gap">
          <SeverityBadge severity={finding.severity} />
          <Badge>{finding.source}</Badge>
          {finding.confidence && <Badge>confidence {finding.confidence}</Badge>}
          {finding.exposure && <Badge>{finding.exposure.replaceAll('_', ' ')}</Badge>}
          {finding.priority !== undefined && <Badge>priority {finding.priority}</Badge>}
          <Badge tone="neutral">{finding.disposition.replaceAll('_', ' ')}</Badge>
        </div>
        {finding.secret && (
          <div className="detail-row">
            <span>Secret classification</span>
            <strong>
              {finding.secret.classification.replaceAll('_', ' ')}
              {finding.secret.commit ? ` · commit ${finding.secret.commit.slice(0, 12)}` : ''}
            </strong>
          </div>
        )}
        <h2 id="finding-title" className="finding-title">
          {finding.title}
        </h2>
        <p>{finding.description}</p>
        <div className="notice">
          <Icon name="info" />
          <span>
            Scanner detection and model assessment are not proof of exploitability. A human decision
            is tracked separately.
          </span>
        </div>
        <section>
          <h3 className="section-label">Evidence</h3>
          {finding.evidence.map((evidence) => (
            <div className="evidence" key={evidence.id}>
              <div className="code-header">
                <Icon name="code" size={15} />
                <span>
                  {evidence.file}: {evidence.startLine} – {evidence.endLine}
                </span>
                <Badge>{evidence.scope ?? evidence.kind ?? 'source'}</Badge>
              </div>
              <pre className="code-block">{evidence.excerpt}</pre>
              <p className="small">{evidence.observation}</p>
              <span className="digest">SHA-256 {evidence.fileDigest.slice(0, 16)} …</span>
            </div>
          ))}
        </section>
        {finding.runtimeVerification && (
          <section>
            <h3 className="section-label">Runtime reconciliation</h3>
            <div className="row gap">
              <Badge
                tone={finding.runtimeVerification.status === 'corroborated' ? 'medium' : 'success'}
              >
                {finding.runtimeVerification.status.replaceAll('_', ' ')}
              </Badge>
              <span className="small mono">{finding.runtimeVerification.url}</span>
            </div>
            <p>{finding.runtimeVerification.observation}</p>
          </section>
        )}
        {finding.vulnerability && (
          <section>
            <h3 className="section-label">Advisory metadata</h3>
            <div className="detail-row">
              <span>Advisory</span>
              <strong className="mono">{finding.vulnerability.id}</strong>
            </div>
            <div className="detail-row">
              <span>Package</span>
              <strong className="mono">
                {finding.vulnerability.package}@{finding.vulnerability.version}
              </strong>
            </div>
            <div className="detail-row">
              <span>Dependency</span>
              <strong>{finding.vulnerability.relationship}</strong>
            </div>
            <div className="detail-row">
              <span>Source reachability</span>
              <strong>{finding.vulnerability.reachability ?? 'unknown'}</strong>
            </div>
            <div className="detail-row">
              <span>Aliases</span>
              <span className="mono small">
                {finding.vulnerability.aliases.join(', ') || 'None'}
              </span>
            </div>
            <div className="detail-row">
              <span>Severity data</span>
              <span className="mono small">
                {finding.vulnerability.severity
                  .map((item) => `${item.type}: ${item.score}`)
                  .join(', ') || 'Not supplied'}
              </span>
            </div>
            <div className="detail-row">
              <span>Known fixed versions</span>
              <span className="mono small">
                {finding.vulnerability.fixedVersions.join(', ') || 'Not listed'}
              </span>
            </div>
            {finding.vulnerability.advisoryModified && (
              <div className="detail-row">
                <span>Advisory modified</span>
                <span className="mono small">{finding.vulnerability.advisoryModified}</span>
              </div>
            )}
          </section>
        )}
        {finding.analysis && (
          <section>
            <h3 className="section-label">
              Contextual assessment
              <Badge>{finding.analysis.kind}</Badge>
            </h3>
            <p>{finding.analysis.explanation}</p>
            <div className="small muted">
              {finding.analysis.inspectedFiles.length} file(s) inspected · {finding.analysis.rounds}{' '}
              round(s) · {finding.analysis.assessment.replaceAll('_', ' ')}
            </div>
            {finding.analysis.provider && (
              <div className="small muted">
                Provider {finding.analysis.provider} · model {finding.analysis.model ?? 'unknown'} ·
                prompt {finding.analysis.promptVersion ?? 'unknown'} · confidence{' '}
                {finding.analysis.confidence ?? 'not supplied'} ·{' '}
                {finding.analysis.cached ? 'cache hit' : 'fresh analysis'}
              </div>
            )}
            {finding.analysis.impact && (
              <div className="detail-row">
                <span>Likely impact</span>
                <span>{finding.analysis.impact}</span>
              </div>
            )}
            {[
              { label: 'Controls found', items: finding.analysis.controlsFound },
              { label: 'Missing evidence', items: finding.analysis.missingEvidence },
              { label: 'Preconditions', items: finding.analysis.preconditions },
              { label: 'Remediation options', items: finding.analysis.remediationOptions },
              { label: 'Safe verification plan', items: finding.analysis.verificationPlan },
            ].map(({ label, items }) =>
              items?.length ? (
                <div key={label}>
                  <h4>{label}</h4>
                  <ul className="limitations">
                    {items.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
              ) : null,
            )}
            <h4>Analysis limitations</h4>
            <ul className="limitations">
              {finding.analysis.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </section>
        )}
        {finding.provenance && (
          <section>
            <h3 className="section-label">Provenance</h3>
            <div className="detail-row">
              <span>Detected by</span>
              <strong>{finding.provenance.detector.replaceAll('-', ' ')}</strong>
            </div>
            <div className="detail-row">
              <span>Scanner / rule</span>
              <span className="mono small">
                {finding.provenance.scanner}
                {finding.provenance.scannerVersion
                  ? ` ${finding.provenance.scannerVersion}`
                  : ''} · {finding.provenance.ruleId}
              </span>
            </div>
            <div className="detail-row">
              <span>Evidence</span>
              <span>{finding.provenance.evidenceKinds.join(', ')}</span>
            </div>
          </section>
        )}
        <section>
          <h3 className="section-label">Recommended next step</h3>
          <p>{finding.remediation}</p>
          <div className="row gap">
            {finding.cwe.map((cwe) => (
              <Badge key={cwe}>{cwe}</Badge>
            ))}
          </div>
        </section>
        <section className="review-section">
          <h3 className="section-label">Project exception</h3>
          {finding.suppression ? (
            <>
              <p>{finding.suppression.reason}</p>
              <p className="small muted">
                Active since {finding.suppression.createdAt}
                {finding.suppression.expiresAt
                  ? ` · expires ${finding.suppression.expiresAt}`
                  : ' · no expiry'}
                . The finding remains in reports.
              </p>
              <button
                className="button"
                disabled={!reviewable || pending}
                onClick={() => void updateSuppression(true)}
              >
                Remove exception
              </button>
            </>
          ) : (
            <>
              <label htmlFor="suppression-reason">Reason</label>
              <textarea
                id="suppression-reason"
                rows={3}
                value={suppressionReason}
                maxLength={2000}
                onChange={(event) => setSuppressionReason(event.target.value)}
                placeholder="Explain why this exact fingerprint may be ignored in future audits."
                disabled={!reviewable}
              />
              <label htmlFor="suppression-expiry">Expiry (optional)</label>
              <input
                id="suppression-expiry"
                type="date"
                value={suppressionExpiry}
                onChange={(event) => setSuppressionExpiry(event.target.value)}
                disabled={!reviewable}
              />
              <p className="small muted">
                Applies only to this project and exact fingerprint. Expired exceptions stop
                affecting CI automatically.
              </p>
              <button
                className="button"
                disabled={!reviewable || pending || suppressionReason.trim().length < 12}
                onClick={() => void updateSuppression(false)}
              >
                Add project exception
              </button>
            </>
          )}
        </section>
        <section className="review-section">
          <h3 className="section-label">Human review</h3>
          <label htmlFor="review-disposition">Disposition</label>
          <select
            id="review-disposition"
            value={disposition}
            disabled={!reviewable}
            onChange={(event) => setDisposition(event.target.value as Disposition)}
          >
            <option value="needs_review">Needs review</option>
            <option value="confirmed">Confirmed by reviewer</option>
            <option value="false_positive">False positive</option>
            <option value="accepted_risk">Accepted risk</option>
          </select>
          <label htmlFor="review-note">Evidence and rationale</label>
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
            This is an analyst assertion, not an automatically verified exploit. At least 12
            characters are required.
          </p>
          <button
            className="button primary"
            disabled={!reviewable || pending || note.trim().length < 12}
            onClick={save}
          >
            Save review
          </button>
          {error && (
            <p className="error-text" role="alert">
              {error}
            </p>
          )}
        </section>
      </div>
    </dialog>
  );
}
