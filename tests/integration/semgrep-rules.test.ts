import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { scanExternal } from '../../src/scanners/external.ts';
import { snapshotOf } from '../helpers.ts';

const hasSemgrep = spawnSync('semgrep', ['--version'], { stdio: 'ignore' }).status === 0;

test(
  'trusted Semgrep rules cover supplemental Node security mechanics',
  { skip: !hasSemgrep },
  async (context) => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'traceward-semgrep-rules-'));
    context.after(() => rm(temporary, { recursive: true, force: true }));
    const source = `
    import jwt from 'jsonwebtoken';
    import vm from 'node:vm';
    import https from 'node:https';

    export function inspect(token, key, code, users, response, error) {
      jwt.decode(token);
      jwt.verify(token, key, { ignoreExpiration: true });
      vm.runInNewContext(code, {});
      const agent = new https.Agent({ rejectUnauthorized: false });
      users.find({ $where: code });
      response.json({ message: 'failed', stack: error.stack });
      return agent;
    }

    export function safe(token, key, response) {
      jwt.verify(token, key, { algorithms: ['RS256'] });
      response.json({ message: 'failed' });
    }
  `;
    const result = await scanExternal(
      'semgrep',
      snapshotOf(source, 'src/security.ts'),
      true,
      temporary,
      path.resolve('configs'),
    );
    const rules = new Set(result.findings.map((finding) => finding.ruleId));
    for (const rule of [
      'traceward.jwt-decode-review',
      'traceward.jwt-ignore-expiration',
      'traceward.node-vm-execution',
      'traceward.disabled-tls-verification',
      'traceward.mongodb-where-review',
      'traceward.error-stack-response',
    ])
      assert.ok(rules.has(rule), `${rule} was not reported: ${JSON.stringify(result)}`);
    assert.equal(
      result.findings.find((finding) => finding.ruleId === 'traceward.jwt-ignore-expiration')
        ?.category,
      'authentication',
    );
    assert.deepEqual(
      result.findings.find((finding) => finding.ruleId === 'traceward.disabled-tls-verification')
        ?.cwe,
      ['CWE-295'],
    );
  },
);
