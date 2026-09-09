import { Icon } from '../../components/icon.tsx';
export default function MethodologyPage() {
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">HOW TO READ THE RESULTS</div>
          <h1>Evidence over assurance.</h1>
          <p className="subtitle">
            A scanner finding is the start of a review, not the conclusion.
          </p>
        </div>
        <Icon name="shield" size={40} />
      </div>
      <div className="method-grid">
        {[
          [
            '01',
            'Detect',
            'Bounded pattern checks and optional installed scanners produce review candidates. Original source severity and provenance are retained.',
          ],
          [
            '02',
            'Investigate',
            'LangGraph coordinates a bounded review. Optional Ollama or explicitly enabled OpenAI inference can request limited source context, but cannot run tools or change files.',
          ],
          [
            '03',
            'Review',
            'An analyst inspects evidence and records a disposition with a rationale. A model cannot silently dismiss, confirm or downgrade a finding.',
          ],
          [
            '04',
            'Publish',
            'A persistent human-in-the-loop checkpoint gates report publication. Unresolved findings, excluded scope and scanner failures remain visible.',
          ],
        ].map(([number, title, description]) => (
          <section className="panel method-card" key={number}>
            <span className="method-number">{number}</span>
            <h2>{title}</h2>
            <p>{description}</p>
          </section>
        ))}
      </div>
      <section className="panel prose">
        <h2>What this release does not prove</h2>
        <p>
          Built-in patterns and posture checks are not a full SAST engine. They can match comments,
          miss indirect calls, and cannot establish runtime authorization, RLS, exploitability or
          whole-program data flow. Static discovery of an ID-only lookup does not establish an
          authorization flaw.
        </p>
        <p>
          OSV matching shows known advisories for resolved lockfile versions; it does not establish
          reachability. Secret patterns do not establish whether a credential is active. Model
          confidence is not a calibrated probability. A missing finding is not proof that a
          vulnerability was fixed.
        </p>
        <h2>Privacy boundaries</h2>
        <p>
          AI is disabled by default. Ollama stays local; OpenAI and OSV are separate, explicit
          opt-ins. OpenAI receives only bounded, redacted context and requests store=false. Strict
          offline operation still requires OS-level egress controls. Scanner binaries and local
          model weights must be provisioned beforehand.
        </p>
        <p>
          Source snippets and human notes may still contain sensitive data after best-effort
          redaction. Local files and checkpoints are protected by filesystem permissions, not
          encryption. Do not publish real audit artifacts or run this unauthenticated local service
          on a public interface.
        </p>
        <h2>Read-only is not a sandbox</h2>
        <p>
          The target project is never executed. External scanners parse an isolated file copy, but
          still execute as your OS user. This does not safely contain a malicious native scanner or
          every parser vulnerability. Inspect hostile repositories only in a hardened disposable
          environment.
        </p>
      </section>
    </>
  );
}
