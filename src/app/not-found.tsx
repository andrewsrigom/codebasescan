import Link from 'next/link';
export default function NotFound() {
  return (
    <section className="panel prose">
      <h1>Audit not found.</h1>
      <p>This identifier does not belong to an available local audit.</p>
      <Link className="button primary" href="/audits">
        Back to audit history
      </Link>
    </section>
  );
}
