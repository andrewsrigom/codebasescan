import { store } from '../../../../server/context.ts';
import { boundedJson, localRequestError } from '../../../../security/local-http.ts';
import { record, reviewDecision, text, uuid } from '../../../../domain/validation.ts';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
type Context = {
  params: Promise<{
    id: string;
  }>;
};
export async function GET(request: Request, context: Context) {
  const error = localRequestError(request, process.env.TRACEWARD_PORT ?? '3000');
  if (error)
    return Response.json({ error }, { status: 403 });
  try {
    const id = uuid((await context.params).id);
    const database = store();
    return Response.json({ audit: database.audit(id), events: database.events(id), workerOnline: database.workerOnline() }, { headers: { 'Cache-Control': 'no-store' } });
  }
  catch {
    return Response.json({ error: 'Audit not found.' }, { status: 404 });
  }
}
export async function POST(request: Request, context: Context) {
  const error = localRequestError(request, process.env.TRACEWARD_PORT ?? '3000');
  if (error)
    return Response.json({ error }, { status: 403 });
  try {
    const id = uuid((await context.params).id);
    const input = record(await boundedJson(request));
    const database = store();
    if (input.action === 'publish') {
      const note = text(input.note, 'publication note');
      if (note.length < 12)
        throw new Error('Publication review requires a meaningful note.');
      database.publish(id, note);
    }
    else if (input.action === 'cancel')
      database.cancel(id);
    else if (input.action === 'review')
      database.reviewFinding(id, reviewDecision(input));
    else
      throw new Error('Unsupported audit action.');
    return Response.json({ ok: true });
  }
  catch (cause) {
    return Response.json({ error: cause instanceof Error ? cause.message : 'Action failed.' }, { status: 400 });
  }
}
