import { notFound } from 'next/navigation';
import { store } from '../../../server/context.ts';
import { AuditWorkspace } from '../../../components/audit-workspace.tsx';
import { uuid } from '../../../domain/validation.ts';
import { compareReports } from '../../../domain/comparison.ts';
import { buildRemediationPlan } from '../../../domain/remediation.ts';
import { presentAudit } from '../../../domain/workspace-presentation.ts';
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
  const configuredBaseline = database.projectBaseline(audit.projectId);
  const previous =
    configuredBaseline &&
    configuredBaseline.id !== audit.id &&
    configuredBaseline.createdAt < audit.createdAt
      ? configuredBaseline
      : database
          .audits()
          .find(
            (candidate) =>
              candidate.projectId === audit.projectId &&
              candidate.id !== audit.id &&
              candidate.createdAt < audit.createdAt &&
              candidate.report,
          );
  const history = database
    .audits()
    .filter(
      (candidate) =>
        candidate.projectId === audit.projectId &&
        candidate.id !== audit.id &&
        candidate.id !== previous?.id &&
        candidate.createdAt < audit.createdAt &&
        candidate.report,
    )
    .flatMap((candidate) => (candidate.report ? [candidate.report] : []));
  const comparison =
    audit.report && previous?.report
      ? compareReports(previous.report, audit.report, history)
      : undefined;
  const presented = presentAudit(audit);
  return (
    <AuditWorkspace
      key={audit.id}
      initialAudit={presented.audit}
      initialProjectProfile={presented.projectProfile}
      initialEvents={database.events(id)}
      initialWorkerOnline={database.workerOnline()}
      projects={database.projects().map(({ id, name }) => ({ id, name }))}
      comparison={comparison}
      baselineAuditId={configuredBaseline?.id}
      initialRemediationPlan={audit.report ? buildRemediationPlan(audit.report) : null}
    />
  );
}
