import assert from 'node:assert/strict';
import test from 'node:test';
import { buildAgentContext } from '../../src/domain/agent-context.ts';
import {
  agentContextJsonSchema,
  parseAgentContext,
} from '../../src/domain/agent-context-schema.ts';
import type { ProjectProfile } from '../../src/domain/types.ts';
import { sampleReport } from '../helpers.ts';
import { defaultSaasConfiguration } from '../../src/scanners/declarative-config.ts';
import { parseAuditReport } from '../../src/domain/report-schema.ts';

function embeddedProfile(): ProjectProfile {
  return {
    schemaVersion: 1,
    status: 'complete',
    languages: ['typescript'],
    frameworks: [],
    components: [],
    componentEdges: [],
    entrypoints: [
      {
        id: 'entrypoint-update',
        kind: 'next-route',
        file: 'src/app/api/profile/route.ts',
        line: 1,
        name: 'POST',
        route: '/api/profile',
        methods: ['POST'],
        dynamicParameters: [],
        symbolIds: ['symbol-update'],
      },
    ],
    symbols: [],
    imports: [],
    calls: [
      {
        id: 'call-post-message',
        file: 'src/components/embed.tsx',
        line: 8,
        callee: 'window.parent.postMessage',
      },
    ],
    facts: [
      {
        id: 'fact-auth',
        kind: 'authentication',
        file: 'src/app/api/profile/route.ts',
        line: 3,
        signal: 'verifySession',
      },
      {
        id: 'fact-cookie',
        kind: 'cookie',
        file: 'src/app/api/profile/route.ts',
        line: 2,
        signal: 'cookies.get',
      },
    ],
    filesAnalyzed: 2,
    nodesAnalyzed: 40,
    issues: [],
    truncated: false,
  };
}

test('agent context keeps observed embedded and authentication signals separate from conclusions', () => {
  const report = sampleReport();
  report.projectProfile = embeddedProfile();
  report.coverage = [
    {
      id: 'http-posture',
      label: 'Effective HTTP posture',
      status: 'NOT PERFORMED',
      detail: 'No approved URL was supplied.',
    },
  ];

  const context = buildAgentContext(report);
  assert.deepEqual(parseAgentContext(context), context);
  assert.equal(
    context.signals.find((signal) => signal.id === 'cross-document-messaging')?.status,
    'observed',
  );
  assert.equal(
    context.signals.find((signal) => signal.id === 'browser-session-cookie')?.status,
    'observed',
  );
  assert.equal(
    context.openQuestions.find((question) => question.id === 'deployment-model')?.status,
    'partially_observed',
  );
  assert.equal(
    context.openQuestions.find((question) => question.id === 'csrf-applicability')?.status,
    'partially_observed',
  );
  assert.match(context.coverageWarnings[0] ?? '', /NOT PERFORMED/);
});

test('agent context leaves authentication mechanism and CSRF applicability unresolved without evidence', () => {
  const context = buildAgentContext(sampleReport());
  assert.equal(
    context.openQuestions.find((question) => question.id === 'authentication-mechanism')?.status,
    'unresolved',
  );
  assert.equal(
    context.openQuestions.find((question) => question.id === 'csrf-applicability')?.status,
    'unresolved',
  );
  assert.match(
    context.openQuestions.find((question) => question.id === 'csrf-applicability')?.why ?? '',
    /should not be promoted to a ticket/,
  );
});

test('declared app model narrows investigation but does not establish observed controls', () => {
  const report = sampleReport();
  const profile = embeddedProfile();
  profile.entrypoints = [];
  profile.calls = [];
  profile.facts = [];
  profile.saasSemantics = {
    ...defaultSaasConfiguration,
    sources: ['codebasescan.config.json'],
    context: {
      features: ['authentication', 'tenancy'],
      roles: [],
      sensitiveData: [],
      storageBoundaries: [],
      externalServices: [],
      priorityPaths: [],
      outOfScopePaths: [],
      authenticationMethods: ['cookie'],
      deploymentModel: 'embedded',
      trustedParentOrigins: ['https://parent.example'],
      trustBoundaries: ['browser'],
      tenantIsolation: ['application'],
    },
  };
  report.projectProfile = profile;
  assert.equal(
    parseAuditReport(report).projectProfile?.saasSemantics?.context?.deploymentModel,
    'embedded',
  );
  const context = buildAgentContext(report);
  assert.equal(context.declared?.deploymentModel, 'embedded');
  assert.deepEqual(context.declared?.trustedParentOrigins, ['https://parent.example']);
  assert.equal(
    context.signals.find((item) => item.id === 'browser-session-cookie')?.status,
    'not_observed',
  );
  assert.equal(
    context.openQuestions.find((item) => item.id === 'authentication-mechanism')?.status,
    'unresolved',
  );
  assert.equal(
    context.openQuestions.find((item) => item.id === 'trusted-parent-origins')?.status,
    'unresolved',
  );
  assert.deepEqual(parseAgentContext(context), context);
});

test('agent context schema is versioned', () => {
  const schema = agentContextJsonSchema() as {
    properties?: { schemaVersion?: { const?: number } };
  };
  assert.equal(schema.properties?.schemaVersion?.const, 1);
});
