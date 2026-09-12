import test from 'node:test';
import assert from 'node:assert/strict';
import { scanPrivacyStatic } from '../../src/scanners/privacy-static.ts';
import { snapshotOf } from '../helpers.ts';

test('privacy rules find sensitive URL, logging, and browser-storage candidates', () => {
  const result = scanPrivacyStatic(
    snapshotOf(`
      params.set('access_token', accessToken);
      logger.info({ email });
      localStorage.setItem('customer_email', email);
    `),
  );
  assert.deepEqual(
    result.findings.map((finding) => finding.ruleId),
    ['TW-PRIV001', 'TW-PRIV002', 'TW-PRIV003'],
  );
});

test('non-sensitive keys and protected log values avoid privacy candidates', () => {
  const result = scanPrivacyStatic(
    snapshotOf(`
      params.set('theme', theme);
      logger.info({ email: redact(email) });
      console.log(config.sourceAuthors.emails.length);
      logger.info({ emailCount: emails.length, sessionCount: sessions.size });
      logger.error(pluggyCredentialErrorCode(error));
      localStorage.setItem('theme', theme);
    `),
  );
  assert.deepEqual(result.findings, []);
});

test('raw sensitive values remain candidates beside safe aggregate counts', () => {
  const result = scanPrivacyStatic(
    snapshotOf(`
      logger.info({ emailCount: emails.length });
      logger.info({ email: user.email });
      logger.info(credentialErrorCode(accessToken));
    `),
  );
  assert.deepEqual(
    result.findings.map((finding) => finding.ruleId),
    ['TW-PRIV002', 'TW-PRIV002'],
  );
});

test('sensitive words in a static log message are not treated as logged data', () => {
  const result = scanPrivacyStatic(
    snapshotOf(`
      logger.info('Session check finished without an authenticated user');
      logger.warn('Never print passwords, tokens, email addresses, or raw logs');
      logger.info(\`session state: \${sanitize(session)}\`);
    `),
  );
  assert.deepEqual(result.findings, []);
});

test('diagnostic metadata about secret scanning is not treated as secret data', () => {
  const result = scanPrivacyStatic(
    snapshotOf(`
      console.error(JSON.stringify({ check: 'secrets', status: 'error', findings }, null, 2));
      console.log(JSON.stringify({ check: 'secrets', status: 'ok', findings: 0 }));
      logger.warn({ event: 'logging.redaction_check', outcome: 'safe' });
    `),
  );
  assert.deepEqual(result.findings, []);
});

test('sensitive values nested in serialized log objects remain candidates', () => {
  const result = scanPrivacyStatic(
    snapshotOf(`console.error(JSON.stringify({ status: 'error', payload: { accessToken } }));`),
  );
  assert.deepEqual(
    result.findings.map((finding) => finding.ruleId),
    ['TW-PRIV002'],
  );
});

test('sensitive template expressions remain privacy candidates', () => {
  const result = scanPrivacyStatic(snapshotOf('logger.info(`signed in as ${email}`);'));
  assert.deepEqual(
    result.findings.map((finding) => finding.ruleId),
    ['TW-PRIV002'],
  );
});
