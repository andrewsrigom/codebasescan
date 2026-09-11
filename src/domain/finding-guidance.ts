import type { Finding } from './types.ts';

export function humanFindingSource(source: Finding['source']): string {
  const labels: Record<Finding['source'], string> = {
    builtin: 'Source review',
    posture: 'Security posture',
    ast: 'Code flow',
    saas: 'SaaS control',
    next: 'Next.js check',
    react: 'React check',
    accessibility: 'Accessibility check',
    axe: 'Imported Axe result',
    web: 'Web posture check',
    privacy: 'Privacy check',
    reliability: 'Reliability check',
    environment: 'Environment check',
    'supply-chain': 'Supply-chain check',
    'http-probe': 'Runtime observation',
    osv: 'Dependency advisory',
    semgrep: 'Security rule',
    gitleaks: 'Secret scan',
  };
  return labels[source];
}

export function humanFindingImpact(finding: Finding): string {
  if (finding.analysis?.impact) return finding.analysis.impact;
  const impacts: Record<Finding['category'], string> = {
    authentication: 'authentication boundaries and who can enter a protected flow',
    authorization: 'which users or tenants can read data or perform privileged actions',
    injection: 'whether untrusted input can influence a privileged interpreter or operation',
    secrets: 'credential exposure, unintended access, or the need to rotate a real secret',
    configuration: 'the effective protection provided by application or deployment settings',
    'ai-security': 'the trust boundary between untrusted content, model output, and tools',
    dependencies: 'the security and integrity of code included through the dependency graph',
    accessibility: 'whether people using keyboards or assistive technology can use the interface',
    privacy: 'how personal or sensitive data is collected, exposed, retained, or transferred',
    reliability: 'timeouts, retries, duplicate work, cleanup, and predictable failure behavior',
    code: 'maintainability and the chance that concentrated complexity hides future defects',
  };
  return `If confirmed, this could affect ${impacts[finding.category]}. The ${finding.severity} label comes from the detector; this report does not establish runtime exploitability.`;
}

export function humanVerificationSteps(finding: Finding): string[] {
  if (finding.vulnerability)
    return [
      `Confirm that ${finding.vulnerability.package}@${finding.vulnerability.version} is installed through the listed dependency path.`,
      'Check whether the affected feature is referenced and compare the installed version with the advisory fix range.',
    ];
  if (finding.secret)
    return [
      'Determine whether the redacted match is a real credential, a test fixture, or generated sample data.',
      'If it is real, verify exposure and rotation outside this report before closing the candidate.',
    ];
  if (finding.category === 'accessibility')
    return [
      'Render the affected state in an authorized browser and inspect the named control.',
      'Repeat the interaction with keyboard navigation and the relevant assistive-technology check.',
    ];
  if (finding.source === 'http-probe' || finding.runtimeVerification)
    return [
      'Repeat the observation against the intended authorized environment and affected route.',
      'Confirm that redirects, caches, proxies, and authenticated states do not change the result.',
    ];
  if (finding.category === 'configuration')
    return [
      'Trace the captured declaration to the effective environment or framework configuration.',
      'Verify the resulting runtime behavior separately; source declarations alone are not proof.',
    ];
  return [
    'Start at the cited line and trace the value or operation through the local guards shown in source.',
    'Confirm the input, caller, authorization context, and final operation before accepting or rejecting the candidate.',
  ];
}

export function humanFindingLimitations(
  finding: Finding,
  ruleLimitations: string[] = [],
): string[] {
  const fallback = 'Review the cited evidence and scanner coverage before deciding.';
  return [
    ...new Set([
      ...(ruleLimitations.length > 0 ? ruleLimitations : [fallback]),
      ...(finding.analysis?.limitations ?? []),
    ]),
  ];
}
