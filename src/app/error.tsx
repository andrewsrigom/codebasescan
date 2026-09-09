'use client';
export default function ErrorPage({ reset }: {
  reset: () => void;
}) {
  return <section className="panel prose">
    <h1>
      The workspace could not load.
    </h1>
    <p>
      Check the local database, configuration, and terminal output. No successful audit is implied by this error.
    </p>
    <button className="button primary" onClick={reset}>
      Try again
    </button>
  </section>;
}
