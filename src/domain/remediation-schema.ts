import { z } from 'zod';
import type { RemediationPlan, RemediationResult } from './remediation.ts';

const shortText = z.string().max(10_000);
const stringList = z.array(shortText).max(10_000);
const severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const taskKind = z.enum([
  'upgrade_dependency',
  'patch_source',
  'review_configuration',
  'investigate_finding',
  'verify_control',
  'add_test',
]);
const checkKind = z.enum([
  'finding_absent',
  'control_evidenced',
  'project_tests',
  'project_build',
  'traceward_rescan',
]);
const confidence = z.enum(['low', 'medium', 'high']);
const exposure = z.enum(['potentially_public', 'authenticated', 'local', 'unknown']);
const changeRisk = z.enum(['low', 'medium', 'high']);

const priorityFactor = z.object({
  kind: z.enum(['severity', 'exposure', 'confidence', 'reachability', 'control_status']),
  score: z.number().int().min(0).max(100),
  rationale: shortText,
});

const rootCause = z.object({
  id: shortText.regex(/^cause-[a-f0-9]{16}$/),
  kind: z.enum(['dependency', 'rule_location', 'control']),
  key: shortText,
  summary: shortText,
});

const verificationCommand = z.object({
  id: shortText,
  kind: z.enum(['traceward_rescan', 'project_test', 'project_build']),
  argv: z.array(shortText).min(1).max(32),
  workingDirectory: z.literal('project_root'),
  timeoutSeconds: z.number().int().min(1).max(3_600),
  network: z.enum(['denied', 'requires_approval']),
  requiresApproval: z.boolean(),
  source: z.enum(['traceward', 'project_context']),
});

const findingRef = z.object({
  id: shortText,
  fingerprint: shortText,
  ruleId: shortText,
  severity,
});

const acceptanceCheck = z.object({
  id: shortText,
  kind: checkKind,
  required: z.boolean(),
  description: shortText,
});

const task = z.object({
  id: shortText,
  kind: taskKind,
  status: z.enum(['ready', 'blocked', 'needs_human']),
  priority: z.number().int().min(0).max(100),
  priorityFactors: z.array(priorityFactor).min(3).max(8),
  severity,
  confidence,
  exposure,
  title: shortText,
  rationale: shortText,
  rootCause,
  findings: z.array(findingRef).max(10_000),
  controlIds: stringList,
  evidenceIds: stringList,
  files: stringList,
  dependsOn: stringList,
  target: z.object({
    type: z.enum(['dependency', 'source', 'configuration', 'control']),
    package: shortText.optional(),
    currentVersion: shortText.optional(),
    fixCandidate: shortText.optional(),
    relationship: z.enum(['direct', 'transitive', 'unknown']).optional(),
    parentChains: z.array(z.array(shortText).min(2).max(14)).max(3).optional(),
  }),
  instructions: stringList,
  expectedChanges: stringList,
  acceptanceChecks: z.array(acceptanceCheck).max(100),
  verificationCommands: z.array(verificationCommand).max(20),
  changeRisk,
  autoFixable: z.boolean(),
  requiresHuman: z.boolean(),
  constraints: z.object({
    execution: z.literal('plan_only'),
    network: z.enum(['denied', 'requires_approval']),
    allowMajorUpgrade: z.boolean(),
    allowUnrelatedChanges: z.literal(false),
    allowedPaths: stringList,
  }),
  uncertainties: stringList,
});

const planSchema = z.object({
  schemaVersion: z.literal(3),
  kind: z.literal('traceward-remediation-plan'),
  createdAt: shortText,
  audit: z.object({
    id: shortText,
    projectName: shortText,
    snapshotDigest: shortText,
    reportSchemaVersion: z.union([
      z.literal(1),
      z.literal(2),
      z.literal(3),
      z.literal(4),
      z.literal(5),
      z.literal(6),
    ]),
  }),
  policy: stringList,
  summary: z.object({
    tasks: z.number().int().nonnegative().max(2_000),
    rootCauseGroups: z.number().int().nonnegative().max(2_000),
    ready: z.number().int().nonnegative().max(2_000),
    blocked: z.number().int().nonnegative().max(2_000),
    needsHuman: z.number().int().nonnegative().max(2_000),
    autoFixable: z.number().int().nonnegative().max(2_000),
    requiresHuman: z.number().int().nonnegative().max(2_000),
    byKind: z.record(taskKind, z.number().int().nonnegative().max(2_000)),
    omittedReviewedFindings: z.number().int().nonnegative(),
    truncated: z.boolean(),
  }),
  tasks: z.array(task).max(2_000),
  limitations: stringList,
});

const resultSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal('traceward-remediation-result'),
  generatedAt: shortText,
  planDigest: shortText,
  before: z.object({ auditId: shortText, snapshotDigest: shortText }),
  after: z.object({ auditId: shortText, snapshotDigest: shortText }),
  summary: z.object({
    resolved: z.number().int().nonnegative(),
    partial: z.number().int().nonnegative(),
    remaining: z.number().int().nonnegative(),
    not_evaluated: z.number().int().nonnegative(),
    newFindings: z.number().int().nonnegative(),
    snapshotChanged: z.boolean(),
  }),
  taskResults: z
    .array(
      z.object({
        taskId: shortText,
        outcome: z.enum(['resolved', 'partial', 'remaining', 'not_evaluated']),
        resolvedFindingIds: stringList,
        remainingFindingIds: stringList,
        verification: z
          .array(
            z.object({
              checkId: shortText,
              status: z.enum(['passed', 'failed', 'not_run']),
              detail: shortText,
            }),
          )
          .max(100),
      }),
    )
    .max(2_000),
  newFindingIds: stringList,
  changedFiles: stringList,
  limitations: stringList,
});

export function parseRemediationPlan(value: unknown): RemediationPlan {
  return planSchema.parse(value) as RemediationPlan;
}

export function remediationPlanJsonSchema(): unknown {
  return z.toJSONSchema(planSchema, {
    target: 'draft-07',
    unrepresentable: 'throw',
  });
}

export function parseRemediationResult(value: unknown): RemediationResult {
  return resultSchema.parse(value) as RemediationResult;
}
