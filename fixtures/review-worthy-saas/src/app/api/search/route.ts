import { database } from '../../../lib/database';

export async function GET(request: Request) {
  const term = new URL(request.url).searchParams.get('term');
  const records = await database.$queryRawUnsafe(`SELECT name FROM projects WHERE name = '${term}'`);
  return Response.json(records);
}
