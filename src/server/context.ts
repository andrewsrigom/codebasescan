import { configuration } from './config.ts';
import { AuditStore } from './store.ts';
const globalStore = globalThis as unknown as {
  codebasescanStore?: AuditStore;
};
export function store(): AuditStore {
  globalStore.codebasescanStore ??= new AuditStore(configuration().databasePath);
  return globalStore.codebasescanStore;
}
