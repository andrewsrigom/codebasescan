import test from 'node:test';
import assert from 'node:assert/strict';
import { profileProject } from '../../src/scanners/project-profile.ts';
import { scanReliabilityStatic } from '../../src/scanners/reliability-static.ts';
import { snapshotOf } from '../helpers.ts';

test('reliability rules find direct unbounded requests and empty catch blocks', () => {
  const snapshot = snapshotOf(
    `export async function POST() {
      try { return await fetch('https://service.example/data'); } catch {}
    }`,
    'src/app/api/sync/route.ts',
  );
  const result = scanReliabilityStatic(snapshot, profileProject(snapshot).profile);
  assert.deepEqual(result.findings.map((finding) => finding.ruleId).sort(), [
    'TW-REL001',
    'TW-REL002',
  ]);
});

test('bounded outbound calls and explicit failure handling avoid reliability candidates', () => {
  const snapshot = snapshotOf(
    `export async function POST() {
      try {
        return await fetch('https://service.example/data', { signal: AbortSignal.timeout(5000) });
      } catch (error) { throw new Error('Sync failed', { cause: error }); }
    }`,
    'src/app/api/sync/route.ts',
  );
  const result = scanReliabilityStatic(snapshot, profileProject(snapshot).profile);
  assert.deepEqual(result.findings, []);
});

test('a documented narrow ignore is not an undocumented empty catch', () => {
  const snapshot = snapshotOf(`
    export function remember(value) {
      try { localStorage.setItem('preference', value); }
      catch { /* Storage can be unavailable in a browser sandbox. */ }
    }
  `);
  const result = scanReliabilityStatic(snapshot, profileProject(snapshot).profile);
  assert.deepEqual(result.findings, []);
});

test('explicit fallback control flow is not treated as a swallowed failure', () => {
  const snapshot = snapshotOf(`
    export function parseCandidate(raw) {
      try { return JSON.parse(raw); } catch {}
      for (const candidate of raw.split('\\n')) {
        try { return JSON.parse(candidate); } catch {}
      }
      return null;
    }

    export async function waitForReady(attempts) {
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        try { return await probe(); } catch {}
      }
      throw new Error('Probe failed');
    }

    export async function loadOptional() {
      let existing = '';
      try { existing = await readFile('optional.md', 'utf8'); } catch {}
      return existing;
    }

    export async function connect(client) {
      try { await client.connect(); }
      catch (error) {
        try { await client.end(); } catch {}
        throw error;
      }
    }
  `);
  const result = scanReliabilityStatic(snapshot, profileProject(snapshot).profile);
  assert.deepEqual(result.findings, []);
});

test('fallback-looking loops still report discarded failures without an explicit terminal error', () => {
  const snapshot = snapshotOf(`
    export async function collectCatalog(definitions) {
      const catalog = [];
      for (const definition of definitions) {
        try { catalog.push(await loadPrice(definition)); } catch {}
      }
      return catalog;
    }
  `);
  const result = scanReliabilityStatic(snapshot, profileProject(snapshot).profile);
  assert.deepEqual(result.findings.map((finding) => finding.ruleId), ['TW-REL002']);
});
