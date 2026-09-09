import { store } from '../../../server/context.ts';
import { boundedJson, localRequestError } from '../../../security/local-http.ts';
import { auditOptions, record, uuid } from '../../../domain/validation.ts';
import { estimateProjectScope } from '../../../security/paths.ts';
export const runtime = 'nodejs';
export async function POST(request: Request) {
  const error = localRequestError(request, process.env.TRACEWARD_PORT ?? '3000');
  if (error) return Response.json({ error }, { status: 403 });
  try {
    const input = record(await boundedJson(request));
    const projectId = uuid(input.projectId);
    if (input.approveTruncation !== undefined && typeof input.approveTruncation !== 'boolean')
      throw new Error('approveTruncation must be a boolean.');
    const database = store();
    const estimate = await estimateProjectScope(database.project(projectId).root);
    const truncationApproved = input.approveTruncation === true;
    if (estimate.predictedTruncated && !truncationApproved)
      throw new Error(
        `The source snapshot is expected to be partial (${estimate.reasons.join(', ')}). Review the estimate and explicitly approve truncation.`,
      );
    const audit = database.enqueue(projectId, {
      ...auditOptions(input),
      scopePreflight: { ...estimate, truncationApproved },
    });
    return Response.json(
      { id: audit.id, scopePreflight: audit.options.scopePreflight },
      { status: 201 },
    );
  } catch (cause) {
    return Response.json(
      { error: cause instanceof Error ? cause.message : 'Could not queue audit.' },
      { status: 400 },
    );
  }
}
