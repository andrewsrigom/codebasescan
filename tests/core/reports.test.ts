import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, toHtml, toMarkdown, toSarif } from '../../src/domain/reports.ts';
import { sampleReport } from '../helpers.ts';
test('HTML export escapes source and titles rather than executing them', () => {
  const report = sampleReport();
  report.projectName = '<script>alert(1)</script>';
  report.findings[0]!.evidence[0]!.excerpt = '<img src=x onerror=alert(1)>';
  const output = toHtml(report);
  assert.ok(!output.includes('<script>'));
  assert.ok(!output.includes('<img src=x'));
  assert.ok(output.includes('&lt;script&gt;'));
  assert.ok(output.includes("default-src 'none'"));
});
test('SARIF export retains unresolved status and valid local locations', () => {
  const result = toSarif(sampleReport()) as {
    version: string;
    runs: {
      results: {
        properties: {
          disposition: string;
        };
      }[];
    }[];
  };
  assert.equal(result.version, '2.1.0');
  assert.equal(result.runs[0]?.results[0]?.properties.disposition, 'needs_review');
});
test('Markdown includes scope and limitations', () => {
  const output = toMarkdown(sampleReport());
  assert.ok(output.includes('not a security certification'));
  assert.ok(output.includes('## Coverage'));
  assert.ok(output.includes('## Limitations'));
});
test('standard HTML metacharacters are escaped', () => {
  assert.equal(escapeHtml('<>&"'), '&lt;&gt;&amp;&quot;');
});
