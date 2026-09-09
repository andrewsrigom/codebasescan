import { ClientPanel } from '../components/client-panel';

export default async function Page() {
  const session = await getSession();
  return <ClientPanel session={session} html="" destination="/" token="" />;
}
