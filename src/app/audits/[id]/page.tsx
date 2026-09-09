import { notFound } from 'next/navigation';
import { store } from '../../../server/context.ts';
import { AuditWorkspace } from '../../../components/audit-workspace.tsx';
import { uuid } from '../../../domain/validation.ts';
import { compareReports } from '../../../domain/comparison.ts';
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';
export default async function AuditPage({
  params,
}: {
  params: Promise<{
    id: string;
  }>;
}) {
  const database = store();
  const { id } = await params;
  let audit;
  try {
    audit = database.audit(uuid(id));
  } catch {
    notFound();
  }
  const previous = database
    .audits()
    .find(
      (candidate) =>
        candidate.projectId === audit.projectId &&
        candidate.id !== audit.id &&
        candidate.createdAt < audit.createdAt &&
        candidate.report,
    );
  const comparison =
    audit.report && previous?.report ? compareReports(previous.report, audit.report) : undefined;
  return (
    <AuditWorkspace
      key={audit.id}
      initialAudit={audit}
      initialEvents={database.events(id)}
      initialWorkerOnline={database.workerOnline()}
      projects={database.projects().map(({ id, name }) => ({ id, name }))}
      comparison={comparison}
    />
  );
}
