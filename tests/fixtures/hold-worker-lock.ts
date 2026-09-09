import { AuditStore } from '../../src/server/store.ts';

const databasePath = process.argv[2];
if (!databasePath) throw new Error('Database path is required.');

const store = new AuditStore(databasePath);
const project = store.registerProject('Crash fixture', '/fixture/crash-worker');
const audit = store.enqueue(project.id);
store.acquireWorker();
store.claim(audit.id);
process.stdout.write(`${audit.id}\n`);

setInterval(() => undefined, 60_000);
await new Promise(() => undefined);
