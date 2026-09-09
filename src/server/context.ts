import { configuration } from './config.ts';
import { AuditStore } from './store.ts';
const globalStore = globalThis as unknown as {
  tracewardStore?: AuditStore;
};
export function store(): AuditStore {
  globalStore.tracewardStore ??= new AuditStore(configuration().databasePath);
  return globalStore.tracewardStore;
}
