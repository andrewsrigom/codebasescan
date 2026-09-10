import { store } from '../../../../server/context.ts';
import { boundedJson, localRequestError } from '../../../../security/local-http.ts';
import {
  controlReviewDecision,
  record,
  reviewDecision,
  suppressionDecision,
  text,
  uuid,
} from '../../../../domain/validation.ts';
import { buildRemediationPlan } from '../../../../domain/remediation.ts';
import { presentAudit } from '../../../../domain/workspace-presentation.ts';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
type Context = {
  params: Promise<{
    id: string;
  }>;
};
export async function GET(request: Request, context: Context) {
  const error = localRequestError(
    request,
    process.env.CODEBASESCAN_PORT ?? '3000',
    process.env.CODEBASESCAN_INTERNAL_HOST,
  );
  if (error) return Response.json({ error }, { status: 403 });
  try {
    const id = uuid((await context.params).id);
    const database = store();
    const audit = database.audit(id);
    const presented = presentAudit(audit);
    return Response.json(
      {
        audit: presented.audit,
        projectProfile: presented.projectProfile,
        events: database.events(id),
        workerOnline: database.workerOnline(),
        remediationPlan: audit.report ? buildRemediationPlan(audit.report) : null,
      },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch {
    return Response.json({ error: 'Audit not found.' }, { status: 404 });
  }
}
export async function POST(request: Request, context: Context) {
  const error = localRequestError(
    request,
    process.env.CODEBASESCAN_PORT ?? '3000',
    process.env.CODEBASESCAN_INTERNAL_HOST,
  );
  if (error) return Response.json({ error }, { status: 403 });
  try {
    const id = uuid((await context.params).id);
    const input = record(await boundedJson(request));
    const database = store();
    if (input.action === 'publish') {
      const note = text(input.note, 'publication note');
      if (note.length < 12) throw new Error('Publication review requires a meaningful note.');
      database.publish(id, note);
    } else if (input.action === 'cancel') database.cancel(id);
    else if (input.action === 'review') database.reviewFinding(id, reviewDecision(input));
    else if (input.action === 'review-control')
      database.reviewControl(id, controlReviewDecision(input));
    else if (input.action === 'suppress') database.suppressFinding(id, suppressionDecision(input));
    else if (input.action === 'remove-suppression') {
      const findingId = text(input.findingId, 'finding', 30);
      database.removeSuppression(id, findingId);
    } else if (input.action === 'set-baseline') {
      const audit = database.audit(id);
      database.setProjectBaseline(audit.projectId, id);
    } else throw new Error('Unsupported audit action.');
    return Response.json({ ok: true });
  } catch (cause) {
    return Response.json(
      { error: cause instanceof Error ? cause.message : 'Action failed.' },
      { status: 400 },
    );
  }
}
