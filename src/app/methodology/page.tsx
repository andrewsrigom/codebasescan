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
            'Capture',
            'CodebaseScan creates a bounded, read-only snapshot. Target scripts, dependencies, configuration modules, and application code are never executed.',
          ],
          [
            '02',
            'Analyze',
            'Deterministic TypeScript rules and optional trusted scanners produce review candidates with evidence, provenance, and explicit coverage.',
          ],
          [
            '03',
            'Review',
            'A human or separately authorized coding agent can inspect the report and relevant source. Conclusions remain separate from scanner evidence.',
          ],
          [
            '04',
            'Share',
            'The current static report can be opened locally, attached to CI, or hosted as files after sensitive content is reviewed.',
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
          reachability. Secret patterns do not establish whether a credential is active. A missing
          finding is not proof that a vulnerability was fixed.
        </p>
        <h2>Privacy boundaries</h2>
        <p>
          The audit has no built-in model or cloud-model call. OSV refresh and the bounded HTTP
          probe are separate, explicit network actions. Strict offline operation still requires
          OS-level egress controls. Optional scanner binaries must be provisioned beforehand.
        </p>
        <p>
          Source snippets and human notes may still contain sensitive data after best-effort
          redaction. Local files are protected by filesystem permissions, not encryption. Review
          every report before publishing it, and never expose the unauthenticated review application
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
