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
      localStorage.setItem('theme', theme);
    `),
  );
  assert.deepEqual(result.findings, []);
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

test('sensitive template expressions remain privacy candidates', () => {
  const result = scanPrivacyStatic(snapshotOf('logger.info(`signed in as ${email}`);'));
  assert.deepEqual(
    result.findings.map((finding) => finding.ruleId),
    ['TW-PRIV002'],
  );
});
