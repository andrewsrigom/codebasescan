import path from 'node:path';
import { writeFile } from 'node:fs/promises';
import { configuration } from '../server/config.ts';
import { AuditStore } from '../server/store.ts';
import { validateProjectRoot } from '../security/paths.ts';
import { disableRemoteTracing } from '../security/privacy.ts';
import { toHtml, toMarkdown, toSarif } from '../domain/reports.ts';
disableRemoteTracing();
process.umask(0o077);
const config = configuration();
const store = new AuditStore(config.databasePath);
const [command, target, format = 'json'] = process.argv.slice(2);
try {
  if ((command === 'register' || command === 'scan') && target) {
    const root = await validateProjectRoot(target, config.dataDirectory);
    const project = store.registerProject(path.basename(root), root);
    if (command === 'register')
      console.log(JSON.stringify(project, null, 2));
    else {
      const audit = store.enqueue(project.id);
      console.log(`Queued ${audit.id}. Run npm run worker to process it, then review the report in the local UI.`);
    }
  }
  else if (command === 'list') {
    console.log(JSON.stringify(store.audits().map((audit) => ({ id: audit.id, projectId: audit.projectId, status: audit.status, createdAt: audit.createdAt, updatedAt: audit.updatedAt })), null, 2));
  }
  else if (command === 'export' && target) {
    const report = store.audit(target).report;
    if (!report)
      throw new Error('No report is available for this audit.');
    if (!['json', 'md', 'html', 'sarif'].includes(format))
      throw new Error('Use json, md, html, or sarif.');
    const output = format === 'html' ? toHtml(report) : format === 'md' ? toMarkdown(report) : JSON.stringify(format === 'sarif' ? toSarif(report) : report, null, 2);
    const destination = path.resolve(`traceward-${report.auditId}.${format}`);
    await writeFile(destination, output, { mode: 0o600, flag: 'wx' });
    console.log(`Saved ${destination}`);
  }
  else {
    console.log('Traceward\n\n  npm run cli -- register /path/to/project\n  npm run cli -- scan /path/to/project\n  npm run cli -- list\n  npm run cli -- export <audit-id> json|md|html|sarif');
  }
}
catch (error) {
  console.error(error instanceof Error ? error.message : 'Command failed.');
  process.exitCode = 1;
}
finally {
  store.close();
}
