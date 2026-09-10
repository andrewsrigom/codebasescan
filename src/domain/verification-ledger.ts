import type { AuditReport } from './types.ts';
import { digest } from './findings.ts';
import type { RemediationPlan, RemediationVerificationCommand } from './remediation.ts';

export const verificationLedgerVersion = 1 as const;

export type ExternalVerificationKind = 'project_test' | 'project_build';

export interface VerificationExecution {
  id: string;
  kind: ExternalVerificationKind;
  argv: string[];
  workingDirectory: 'project_root';
  startedAt: string;
  durationMs: number;
  exitCode: number;
  outputSha256: string;
  outputBytes: number;
  outputTruncated: boolean;
  executor: string;
  network: 'denied' | 'used' | 'unknown';
}

export interface VerificationLedger {
  schemaVersion: typeof verificationLedgerVersion;
  kind: 'traceward-verification-ledger';
  createdAt: string;
  project: {
    name: string;
    before: { auditId: string; snapshotDigest: string };
    after: { auditId: string; snapshotDigest: string };
  };
  planDigest: string;
  executions: VerificationExecution[];
}

export interface AppliedVerificationExecution extends VerificationExecution {
  status: 'applied' | 'unmatched';
  matchedTaskIds: string[];
}

export interface ExternalVerificationSummary {
  ledgerDigest: string;
  source: 'external_executor';
  authenticated: false;
  executionsReceived: number;
  executionsApplied: number;
  unmatchedExecutionIds: string[];
  executions: AppliedVerificationExecution[];
}

export interface EvaluatedVerificationLedger {
  summary: ExternalVerificationSummary;
  executionsByCommand: ReadonlyMap<string, VerificationExecution>;
}

export function verificationCommandKey(
  command: Pick<RemediationVerificationCommand, 'kind' | 'argv' | 'workingDirectory'>,
): string {
  return JSON.stringify([command.kind, command.workingDirectory, command.argv]);
}

export function remediationPlanArtifactDigest(plan: RemediationPlan): string {
  return digest(`${JSON.stringify(plan, null, 2)}\n`);
}

export function evaluateVerificationLedger(
  ledger: VerificationLedger,
  plan: RemediationPlan,
  before: AuditReport,
  after: AuditReport,
): EvaluatedVerificationLedger {
  if (ledger.project.name !== before.projectName || before.projectName !== after.projectName)
    throw new Error('Verification ledger belongs to a different project.');
  if (
    ledger.project.before.auditId !== before.auditId ||
    ledger.project.before.snapshotDigest !== before.snapshotDigest
  )
    throw new Error('Verification ledger does not match the baseline audit.');
  if (
    ledger.project.after.auditId !== after.auditId ||
    ledger.project.after.snapshotDigest !== after.snapshotDigest
  )
    throw new Error('Verification ledger does not match the after audit.');
  if (ledger.planDigest !== remediationPlanArtifactDigest(plan))
    throw new Error('Verification ledger does not match the baseline remediation plan.');

  const taskIdsByCommand = new Map<string, Set<string>>();
  for (const task of plan.tasks)
    for (const command of task.verificationCommands) {
      if (command.kind !== 'project_test' && command.kind !== 'project_build') continue;
      const key = verificationCommandKey(command);
      const taskIds = taskIdsByCommand.get(key) ?? new Set<string>();
      taskIds.add(task.id);
      taskIdsByCommand.set(key, taskIds);
    }

  const executionsByCommand = new Map<string, VerificationExecution>();
  const executions = ledger.executions.map((execution): AppliedVerificationExecution => {
    const key = verificationCommandKey(execution);
    const matchedTaskIds = [...(taskIdsByCommand.get(key) ?? [])].sort();
    if (matchedTaskIds.length) executionsByCommand.set(key, execution);
    return {
      ...execution,
      status: matchedTaskIds.length ? 'applied' : 'unmatched',
      matchedTaskIds,
    };
  });
  const unmatchedExecutionIds = executions
    .filter((execution) => execution.status === 'unmatched')
    .map((execution) => execution.id);
  return {
    summary: {
      ledgerDigest: digest(JSON.stringify(ledger)),
      source: 'external_executor',
      authenticated: false,
      executionsReceived: executions.length,
      executionsApplied: executions.length - unmatchedExecutionIds.length,
      unmatchedExecutionIds,
      executions,
    },
    executionsByCommand,
  };
}
