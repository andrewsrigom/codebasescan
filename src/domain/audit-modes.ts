import { auditModes, type AuditMode, type AuditModeSelection } from './types.ts';

export const auditModePackVersion = '0.8.0';

export function resolveAuditModes(selected?: AuditMode[]): AuditMode[] {
  return selected?.length ? [...new Set(selected)] : [...auditModes];
}

export function auditModeSelections(selected?: AuditMode[]): AuditModeSelection[] {
  const enabled = new Set(resolveAuditModes(selected));
  return auditModes.map((id) => ({ id, version: auditModePackVersion, enabled: enabled.has(id) }));
}

export function modeEnabled(selected: Set<AuditMode>, ...required: AuditMode[]): boolean {
  return required.some((mode) => selected.has(mode));
}
