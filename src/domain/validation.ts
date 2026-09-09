import type {
  AuditOptions,
  ControlReviewDecision,
  ReviewDecision,
  SuppressionDecision,
} from './types.ts';
import { redact } from '../security/redact.ts';
export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Expected an object.');
  return value as Record<string, unknown>;
}
export function text(value: unknown, name: string, maximum = 2000): string {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum)
    throw new Error(`Invalid ${name}.`);
  return value.trim();
}
export function uuid(value: unknown): string {
  const id = text(value, 'identifier', 36);
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id))
    throw new Error('Invalid identifier.');
  return id;
}
export function reviewDecision(value: unknown): ReviewDecision {
  const input = record(value);
  const findingId = text(input.findingId, 'finding', 30);
  const disposition = input.disposition;
  if (
    disposition !== 'confirmed' &&
    disposition !== 'false_positive' &&
    disposition !== 'accepted_risk' &&
    disposition !== 'needs_review'
  )
    throw new Error('Invalid review decision.');
  const note = redact(text(input.note, 'review note'));
  if (note.length < 12)
    throw new Error('Explain the decision and supporting evidence in at least 12 characters.');
  return { findingId, disposition, note };
}

export function controlReviewDecision(value: unknown): ControlReviewDecision {
  const input = record(value);
  const controlId = text(input.controlId, 'control', 100);
  const decision = input.decision;
  if (
    decision !== 'verified_external' &&
    decision !== 'accepted_gap' &&
    decision !== 'not_applicable' &&
    decision !== 'needs_follow_up'
  )
    throw new Error('Invalid control review decision.');
  const note = redact(text(input.note, 'control review note'));
  if (note.length < 12)
    throw new Error(
      'Explain the control decision and supporting evidence in at least 12 characters.',
    );
  return { controlId, decision, note };
}

export function suppressionDecision(value: unknown): SuppressionDecision {
  const input = record(value);
  const findingId = text(input.findingId, 'finding', 30);
  const reason = redact(text(input.reason, 'suppression reason'));
  if (reason.length < 12) throw new Error('Explain the exception in at least 12 characters.');
  if (input.expiresAt === undefined) return { findingId, reason };
  const expiresAt = text(input.expiresAt, 'suppression expiry', 100);
  const timestamp = Date.parse(expiresAt);
  if (!Number.isFinite(timestamp) || timestamp <= Date.now())
    throw new Error('Suppression expiry must be a future ISO date.');
  return { findingId, reason, expiresAt: new Date(timestamp).toISOString() };
}

export function auditOptions(value: unknown): AuditOptions {
  const input = record(value);
  if (input.gitHistorySecrets !== undefined && typeof input.gitHistorySecrets !== 'boolean')
    throw new Error('gitHistorySecrets must be a boolean.');
  const result: AuditOptions = {
    ...(input.gitHistorySecrets === true ? { gitHistorySecrets: true } : {}),
  };
  if (input.httpProbe !== undefined) {
    const probe = record(input.httpProbe);
    if (probe.approved !== true)
      throw new Error('The HTTP target must be explicitly approved for this audit.');
    const url = text(probe.url, 'HTTP probe URL', 2048);
    if (probe.allowPrivateNetwork !== undefined && typeof probe.allowPrivateNetwork !== 'boolean')
      throw new Error('allowPrivateNetwork must be a boolean.');
    result.httpProbe = {
      url,
      allowPrivateNetwork: probe.allowPrivateNetwork === true,
    };
  }
  return result;
}
