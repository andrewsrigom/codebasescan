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
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'codebasescan-semgrep-rules-'));
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
      response.logger.info({ token });
      response.logger.error('request failed', { password: key });
      response.serializer.unserialize(code);
      const callback = new URL('https://example.test/callback');
      callback.searchParams.set('access_token', token);
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
      'codebasescan.jwt-decode-review',
      'codebasescan.jwt-ignore-expiration',
      'codebasescan.node-vm-execution',
      'codebasescan.disabled-tls-verification',
      'codebasescan.mongodb-where-review',
      'codebasescan.error-stack-response',
      'codebasescan.sensitive-log-field',
      'codebasescan.unsafe-deserialization-review',
      'codebasescan.token-in-url',
    ])
      assert.ok(rules.has(rule), `${rule} was not reported: ${JSON.stringify(result)}`);
    assert.equal(
      result.findings.filter((finding) => finding.ruleId === 'codebasescan.sensitive-log-field')
        .length,
      2,
    );
    assert.equal(
      result.findings.find((finding) => finding.ruleId === 'codebasescan.jwt-ignore-expiration')
        ?.category,
      'authentication',
    );
    assert.deepEqual(
      result.findings.find((finding) => finding.ruleId === 'codebasescan.disabled-tls-verification')
        ?.cwe,
      ['CWE-295'],
    );

    const safeResult = await scanExternal(
      'semgrep',
      snapshotOf(
        `
        import jwt from 'jsonwebtoken';
        import https from 'node:https';

        export function safe(token, key, users, response, logger, value) {
          jwt.verify(token, key, { algorithms: ['RS256'] });
          const agent = new https.Agent({ rejectUnauthorized: true });
          users.find({ tenantId: value });
          response.json({ message: 'failed' });
          logger.info({ userId: value });
          authClient.signIn.email({ email: value, password: key });
          JSON.stringify({ username: value, password: key });
          database.select({ password: key });
          const callback = new URL('https://example.test/callback');
          callback.searchParams.set('state', value);
          return { agent, parsed: JSON.parse(value) };
        }
      `,
        'src/safe.ts',
      ),
      true,
      temporary,
      path.resolve('configs'),
    );
    assert.equal(safeResult.run.status, 'completed');
    assert.deepEqual(
      safeResult.findings.filter((finding) => finding.ruleId.startsWith('codebasescan.')),
      [],
    );
  },
);
