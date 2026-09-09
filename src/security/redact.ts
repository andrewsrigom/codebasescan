const credentialAssignment = /((?:["']?)[\w.-]*(?:secret|password|passwd|token|api[_-]?key|private[_-]?key|service[_-]?role)[\w.-]*(?:["']?)\s*[:=]\s*)(["'`])([^\r\n]*?)\2/gi;
export function redact(value: string): string {
  return value
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, '[REDACTED PRIVATE KEY]')
    .replace(credentialAssignment, '$1"[REDACTED]"')
    .replace(/\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{8,}\b/g, '[REDACTED TOKEN]')
    .replace(/\b(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{12,}\b/g, '[REDACTED TOKEN]')
    .replace(/\bAKIA[A-Z0-9]{16}\b/g, '[REDACTED KEY]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]{8,}/gi, 'Bearer [REDACTED]')
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[REDACTED]@')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED JWT]')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
}
