import { z } from 'zod';
import {
  agentReviewRulePackJsonSchema,
  parseAgentReviewRulePack,
  type AgentReviewRulePack,
} from './agent-rules.ts';
import { parseRemediationPlan, remediationPlanJsonSchema } from './remediation-schema.ts';
import type { RemediationPlan } from './remediation.ts';

const text = (maximum: number) => z.string().min(1).max(maximum);
const taskGuidanceSchema = z
  .object({
    taskId: text(100),
    ruleIds: z.array(text(100)).min(1).max(20),
    questions: z.array(text(300)).min(1).max(40),
    evidenceRequired: z.array(text(300)).min(1).max(40),
    falsePositiveChecks: z.array(text(300)).min(1).max(40),
    searchHints: z.array(text(100)).min(1).max(50),
    limitations: z.array(text(300)).min(1).max(30),
  })
  .strict();

const agentReportEnvelopeSchema = z
  .object({
    schemaVersion: z.literal(1),
    kind: z.literal('codebasescan-agent-report'),
    createdAt: z.string().datetime(),
    audit: z
      .object({
        id: text(100),
        projectName: text(200),
        snapshotDigest: z.string().regex(/^[a-f0-9]{64}$/),
        reportSchemaVersion: z.number().int().positive(),
      })
      .strict(),
    purpose: z.literal('review_and_discovery'),
    policy: z.array(text(500)).min(1).max(20),
    summary: z
      .object({
        tasks: z.number().int().nonnegative(),
        findingTasks: z.number().int().nonnegative(),
        controlTasks: z.number().int().nonnegative(),
        reviewRules: z.number().int().positive(),
      })
      .strict(),
    depths: z
      .array(
        z
          .object({
            id: z.enum(['quick', 'standard', 'deep']),
            description: text(300),
          })
          .strict(),
      )
      .length(3),
    workflow: z
      .array(
        z
          .object({
            id: z.enum([
              'validate_inputs',
              'triage',
              'investigate',
              'challenge',
              'discover_gaps',
              'report',
            ]),
            objective: text(500),
          })
          .strict(),
      )
      .length(6),
    rulePack: z.unknown(),
    plan: z.unknown(),
    taskGuidance: z.array(taskGuidanceSchema).max(2_000),
    limitations: z.array(text(500)).min(1).max(20),
  })
  .strict();

type AgentReportEnvelope = z.infer<typeof agentReportEnvelopeSchema>;

export interface AgentReport extends Omit<AgentReportEnvelope, 'rulePack' | 'plan'> {
  rulePack: AgentReviewRulePack;
  plan: RemediationPlan;
}

export function parseAgentReport(value: unknown): AgentReport {
  const parsed = agentReportEnvelopeSchema.parse(value);
  const rulePack = parseAgentReviewRulePack(parsed.rulePack);
  const plan = parseRemediationPlan(parsed.plan);
  if (
    parsed.audit.id !== plan.audit.id ||
    parsed.audit.snapshotDigest !== plan.audit.snapshotDigest ||
    parsed.createdAt !== plan.createdAt ||
    parsed.summary.tasks !== plan.tasks.length ||
    parsed.summary.reviewRules !== rulePack.rules.length
  )
    throw new Error('Agent report does not match its remediation plan or rule pack.');
  const taskIds = new Set(plan.tasks.map((task) => task.id));
  const ruleIds = new Set(rulePack.rules.map((rule) => rule.id));
  if (
    parsed.taskGuidance.length !== plan.tasks.length ||
    parsed.taskGuidance.some(
      (guidance) =>
        !taskIds.has(guidance.taskId) || guidance.ruleIds.some((id) => !ruleIds.has(id)),
    )
  )
    throw new Error('Agent report task guidance contains an unknown task or rule.');
  return { ...parsed, rulePack, plan };
}

export function agentReportJsonSchema(): Record<string, unknown> {
  const schema = z.toJSONSchema(agentReportEnvelopeSchema) as Record<string, unknown> & {
    properties?: Record<string, unknown>;
  };
  if (schema.properties) {
    schema.properties.plan = remediationPlanJsonSchema();
    schema.properties.rulePack = agentReviewRulePackJsonSchema();
  }
  return schema;
}
