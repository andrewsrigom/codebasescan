import { notFound } from 'next/navigation';
import { store } from '../../../server/context.ts';
import { AuditWorkspace } from '../../../components/audit-workspace.tsx';
import { uuid } from '../../../domain/validation.ts';
export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';
export default async function AuditPage({ params }: {
  params: Promise<{
    id: string;
  }>;
}) {
  const database = store();
  const { id } = await params;
  let audit;
  try {
    audit = database.audit(uuid(id));
  }
  catch {
    notFound();
  }
  return <AuditWorkspace
    key={audit.id}
    initialAudit={audit}
    initialEvents={database.events(id)}
    initialWorkerOnline={database.workerOnline()}
    projects={database.projects().map(({ id, name }) => ({ id, name }))}
  />;
}
