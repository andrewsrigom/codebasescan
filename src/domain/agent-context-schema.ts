import { z } from 'zod';

const text = (maximum: number) => z.string().min(1).max(maximum);
const signalStatus = z.enum(['observed', 'candidate', 'not_observed', 'unknown']);
const evidencePointer = z
  .object({
    kind: z.enum(['finding', 'fact', 'call', 'runtime']),
    id: text(200),
    file: text(500),
    line: z.number().int().positive().optional(),
    ruleId: text(100).optional(),
    detail: text(500),
  })
  .strict();

const declaredContext = z
  .object({
    features: z
      .array(
        z.enum(['authentication', 'tenancy', 'billing', 'webhooks', 'administration', 'uploads']),
      )
      .max(50),
    roles: z.array(text(80)).max(50),
    sensitiveData: z
      .array(
        z.enum([
          'credentials',
          'personal',
          'financial',
          'health',
          'location',
          'communications',
          'files',
          'analytics',
        ]),
      )
      .max(50),
    storageBoundaries: z.array(text(80)).max(50),
    externalServices: z.array(text(80)).max(50),
    priorityPaths: z.array(text(300)).max(50),
    outOfScopePaths: z.array(text(300)).max(50),
  })
  .strict();

export const agentContextSchema = z
  .object({
    schemaVersion: z.literal(1),
    kind: z.literal('codebasescan-agent-context'),
    createdAt: z.iso.datetime(),
    audit: z
      .object({
        id: text(100),
        projectName: text(200),
        snapshotDigest: z.string().regex(/^[a-f0-9]{64}$/),
        reportSchemaVersion: z.number().int().positive(),
      })
      .strict(),
    observed: z
      .object({
        languages: z.array(z.enum(['typescript', 'javascript'])).max(2),
        frameworks: z
          .array(
            z
              .object({
                id: text(100),
                name: text(200),
                file: text(500),
                line: z.number().int().positive(),
              })
              .strict(),
          )
          .max(100),
        components: z.number().int().nonnegative(),
        entrypoints: z
          .array(z.object({ kind: text(100), count: z.number().int().positive() }).strict())
          .max(50),
        securityFacts: z
          .array(z.object({ kind: text(100), count: z.number().int().positive() }).strict())
          .max(100),
      })
      .strict(),
    declared: declaredContext.nullable(),
    signals: z
      .array(
        z
          .object({
            id: z.enum([
              'authentication-boundary',
              'browser-session-cookie',
              'client-token-state',
              'cross-document-messaging',
              'frame-policy',
              'csrf-control',
            ]),
            status: signalStatus,
            interpretation: text(1_000),
            evidence: z.array(evidencePointer).max(20),
          })
          .strict(),
      )
      .length(6),
    openQuestions: z
      .array(
        z
          .object({
            id: z.enum([
              'deployment-model',
              'authentication-mechanism',
              'trusted-parent-origins',
              'csrf-applicability',
              'runtime-boundaries',
            ]),
            status: z.enum(['unresolved', 'partially_observed', 'observed']),
            question: text(500),
            why: text(1_000),
            evidenceIds: z.array(text(200)).max(20),
          })
          .strict(),
      )
      .length(5),
    coverageWarnings: z.array(text(1_000)).max(200),
    policy: z.array(text(1_000)).min(1).max(20),
    limitations: z.array(text(1_000)).min(1).max(20),
  })
  .strict();

export type AgentContext = z.infer<typeof agentContextSchema>;

export function parseAgentContext(value: unknown): AgentContext {
  return agentContextSchema.parse(value);
}

export function agentContextJsonSchema(): Record<string, unknown> {
  return z.toJSONSchema(agentContextSchema) as Record<string, unknown>;
}
