import { store } from '../../../server/context.ts';
import { boundedJson, localRequestError } from '../../../security/local-http.ts';
import { auditOptions, record, uuid } from '../../../domain/validation.ts';
export const runtime = 'nodejs';
export async function POST(request: Request) {
  const error = localRequestError(request, process.env.TRACEWARD_PORT ?? '3000');
  if (error) return Response.json({ error }, { status: 403 });
  try {
    const input = record(await boundedJson(request));
    const audit = store().enqueue(uuid(input.projectId), auditOptions(input));
    return Response.json({ id: audit.id }, { status: 201 });
  } catch (cause) {
    return Response.json(
      { error: cause instanceof Error ? cause.message : 'Could not queue audit.' },
      { status: 400 },
    );
  }
}
