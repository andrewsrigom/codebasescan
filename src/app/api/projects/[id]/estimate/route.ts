import { store } from '../../../../../server/context.ts';
import { uuid } from '../../../../../domain/validation.ts';
import { estimateProjectScope } from '../../../../../security/paths.ts';
import { localRequestError } from '../../../../../security/local-http.ts';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const error = localRequestError(request, process.env.TRACEWARD_PORT ?? '3000');
  if (error) return Response.json({ error }, { status: 403 });
  try {
    const project = store().project(uuid((await params).id));
    return Response.json(await estimateProjectScope(project.root), {
      headers: { 'Cache-Control': 'no-store' },
    });
  } catch (cause) {
    return Response.json(
      { error: cause instanceof Error ? cause.message : 'Could not estimate project scope.' },
      { status: 400 },
    );
  }
}
