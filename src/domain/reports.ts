import type { AuditReport } from './types.ts';
export function escapeHtml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
export function toMarkdown(report: AuditReport): string {
  const lines = [
    '# Traceward security review', '',
    `Project: ${report.projectName.replaceAll('\n', ' ')}`,
    `Audit: ${report.auditId}`, `Snapshot: ${report.snapshotDigest}`,
    `Publication: ${report.publication}`, `AI mode: ${report.aiMode}`, '',
    '> Findings are review candidates, not a security certification. No findings does not prove safety.', '',
    '## Coverage', '',
    `${report.filesAnalyzed} files analyzed. ${report.truncated ? 'Snapshot was truncated.' : 'Snapshot stayed within configured limits.'}`, '',
    ...report.scanners.map((scanner) => `- ${scanner.name}: ${scanner.status}. ${scanner.detail}`), '',
    '## Findings', '',
  ];
  for (const finding of report.findings) {
    lines.push(`### ${finding.severity.toUpperCase()}: ${finding.title}`, '', `Rule: ${finding.ruleId} | Source: ${finding.source} | Disposition: ${finding.disposition}`, '', finding.description, '', `Remediation: ${finding.remediation}`, '');
    for (const evidence of finding.evidence) {
      lines.push(`Evidence: ${evidence.file}:${evidence.startLine}-${evidence.endLine}`, evidence.observation, '');
    }
    if (finding.analysis)
      lines.push(`Analysis (${finding.analysis.kind}): ${finding.analysis.explanation}`, '', ...finding.analysis.limitations.map((limitation) => `- ${limitation}`), '');
    if (finding.review)
      lines.push(`Human review: ${finding.review.note}`, '');
  }
  lines.push('## Limitations', '', ...report.limitations.map((limitation) => `- ${limitation}`));
  return lines.join('\n');
}
export function toHtml(report: AuditReport): string {
  const e = escapeHtml;
  const findings = report.findings.map((finding) => `<article><div class="meta">${e(finding.severity.toUpperCase())} · ${e(finding.source)} · ${e(finding.disposition)}</div><h2>${e(finding.title)}</h2><p>${e(finding.description)}</p>${finding.evidence.map((evidence) => `<h3>${e(evidence.file)}:${evidence.startLine}</h3><pre>${e(evidence.excerpt)}</pre><p>${e(evidence.observation)}</p>`).join('')}<h3>Remediation</h3><p>${e(finding.remediation)}</p>${finding.analysis ? `<h3>Contextual assessment</h3><p>${e(finding.analysis.explanation)}</p>` : ''}${finding.review ? `<h3>Human review</h3><p>${e(finding.review.note)}</p>` : ''}</article>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>Traceward · ${e(report.projectName)}</title><style>body{background:#f4f6f5;color:#182524;font:16px/1.65 system-ui,sans-serif;margin:0}main{max-width:980px;margin:auto;padding:64px 28px}header{border-bottom:1px solid #d7dfdc;padding-bottom:28px}h1{font-size:40px;letter-spacing:-1.8px;line-height:1.15}h2{font-size:21px;line-height:1.4}h3,.meta{font-size:12px;letter-spacing:.5px;text-transform:uppercase}.meta{color:#576d65}article{background:white;border:1px solid #dce4e0;padding:28px;border-radius:12px;margin:22px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#182524;color:#e6eeea;padding:20px;border-radius:8px;font-size:13px}aside{padding:16px;border-left:3px solid #aa813e;background:#fff8eb}code{overflow-wrap:anywhere;font-size:12px}footer{margin-top:36px;font-size:13px;color:#596c63}@media print{body{background:white}article{break-inside:avoid}}</style></head><body><main><header><div class="meta">TRACEWARD / LOCAL SECURITY REVIEW</div><h1>${e(report.projectName)}</h1><p>${report.findings.length} review candidates · ${report.filesAnalyzed} files · ${e(report.publication)}</p><code>Snapshot ${e(report.snapshotDigest)}</code></header><aside>Evidence-led review, not a security certification. Severity and human disposition are separate. Dependency inventory is not vulnerability matching.</aside><h2>Scanner coverage</h2><ul>${report.scanners.map((scanner) => `<li><strong>${e(scanner.name)}</strong>: ${e(scanner.status)} — ${e(scanner.detail)}</li>`).join('')}</ul>${findings}<footer><h2>Limitations</h2><ul>${report.limitations.map((limitation) => `<li>${e(limitation)}</li>`).join('')}</ul><p>Generated locally by Traceward. No scripts, external fonts, or tracking are embedded in this report.</p></footer></main></body></html>`;
}
export function toSarif(report: AuditReport): object {
  const rules = [...new Map(report.findings.map((finding) => [finding.ruleId, {
    id: finding.ruleId, shortDescription: { text: finding.title },
    fullDescription: { text: finding.description }, help: { text: finding.remediation },
  }])).values()];
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'Traceward', version: '0.1.0', rules } },
      invocations: [{ executionSuccessful: !report.truncated && report.scanners.every((scanner) => scanner.status === 'completed') }],
      results: report.findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: ['critical', 'high'].includes(finding.severity) ? 'error' : finding.severity === 'medium' ? 'warning' : 'note',
        message: { text: `${finding.title}. Disposition: ${finding.disposition}. ${finding.description}` },
        partialFingerprints: { 'traceward/v1': finding.fingerprint },
        locations: finding.evidence.map((evidence) => ({
          physicalLocation: {
            artifactLocation: { uri: evidence.file.split('/').map(encodeURIComponent).join('/') },
            region: { startLine: evidence.startLine, endLine: evidence.endLine },
          }
        })),
        properties: { severity: finding.severity, source: finding.source, disposition: finding.disposition, snapshot: report.snapshotDigest },
        ...(finding.disposition === 'false_positive' ? { suppressions: [{ kind: 'external', justification: finding.review?.note ?? 'Human review' }] } : {}),
      })),
    }],
  };
}
