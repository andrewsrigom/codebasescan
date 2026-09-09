import { store } from '../../../../../server/context.ts';
import { toHtml, toMarkdown, toSarif } from '../../../../../domain/reports.ts';
import { uuid } from '../../../../../domain/validation.ts';
import { localRequestError } from '../../../../../security/local-http.ts';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function GET(
  request: Request,
  {
    params,
  }: {
    params: Promise<{
      id: string;
    }>;
  },
) {
  const error = localRequestError(request, process.env.TRACEWARD_PORT ?? '3000');
  if (error) return new Response(error, { status: 403 });
  try {
    const id = uuid((await params).id);
    const report = store().audit(id).report;
    if (!report) return new Response('No report is available yet.', { status: 409 });
    const format = new URL(request.url).searchParams.get('format') ?? 'json';
    if (!['json', 'md', 'html', 'sarif'].includes(format))
      return new Response('Unsupported export format.', { status: 400 });
    const content =
      format === 'html'
        ? toHtml(report)
        : format === 'md'
          ? toMarkdown(report)
          : JSON.stringify(format === 'sarif' ? toSarif(report) : report, null, 2);
    return new Response(content, {
      headers: {
        'Content-Type':
          format === 'html'
            ? 'text/html; charset=utf-8'
            : format === 'md'
              ? 'text/markdown; charset=utf-8'
              : 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="traceward-${id}.${format}"`,
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch {
    return new Response('Audit not found.', { status: 404 });
  }
}
