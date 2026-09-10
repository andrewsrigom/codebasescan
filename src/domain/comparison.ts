import type {
  AuditComparison,
  AuditReport,
  ComponentLifecycleSummary,
  Finding,
  FindingReference,
  ProjectComponent,
} from './types.ts';

function belongsToComponent(file: string, component: ProjectComponent): boolean {
  if (file === component.manifest) return true;
  if (component.root === '.') return !file.startsWith('../') && !file.startsWith('/');
  return file === component.root || file.startsWith(`${component.root}/`);
}

function componentResolver(report: AuditReport): (finding: Finding) => string[] {
  const profile = report.projectProfile;
  const byFile = new Map<string, Set<string>>();
  for (const item of [
    ...(profile?.entrypoints ?? []),
    ...(profile?.symbols ?? []),
    ...(profile?.imports ?? []),
    ...(profile?.calls ?? []),
    ...(profile?.facts ?? []),
  ]) {
    if (!item.componentId) continue;
    const ids = byFile.get(item.file) ?? new Set<string>();
    ids.add(item.componentId);
    byFile.set(item.file, ids);
  }
  const components = [...(profile?.components ?? [])].sort(
    (left, right) => right.root.length - left.root.length || left.id.localeCompare(right.id),
  );
  return (finding) => {
    const ids = new Set<string>();
    for (const evidence of finding.evidence) {
      const observed = byFile.get(evidence.file);
      if (observed?.size) {
        for (const id of observed) ids.add(id);
        continue;
      }
      const owner = components.find((component) => belongsToComponent(evidence.file, component));
      if (owner) ids.add(owner.id);
    }
    return [...ids].sort();
  };
}

function reference(finding: Finding, components: (finding: Finding) => string[]): FindingReference {
  const componentIds = components(finding);
  return {
    id: finding.id,
    fingerprint: finding.fingerprint,
    ruleId: finding.ruleId,
    title: finding.title,
    severity: finding.severity,
    ...(finding.suppression ? { suppressed: true } : {}),
    ...(componentIds.length ? { componentIds } : {}),
  };
}

function componentSummaries(
  reports: AuditReport[],
  groups: Pick<
    AuditComparison,
    | 'newFindings'
    | 'resolvedFindings'
    | 'unchangedFindings'
    | 'reappearedFindings'
    | 'severityChanges'
    | 'dispositionChanges'
  >,
): ComponentLifecycleSummary[] {
  const names = new Map(
    reports.flatMap((report) =>
      (report.projectProfile?.components ?? []).map((component) => [component.id, component.name]),
    ),
  );
  const summaries = new Map<string | null, ComponentLifecycleSummary>();
  const summary = (componentId: string | null) => {
    const existing = summaries.get(componentId);
    if (existing) return existing;
    const created: ComponentLifecycleSummary = {
      componentId,
      name: componentId ? (names.get(componentId) ?? componentId) : 'Unassigned',
      newFindings: 0,
      resolvedFindings: 0,
      unchangedFindings: 0,
      reappearedFindings: 0,
      severityChanges: 0,
      dispositionChanges: 0,
    };
    summaries.set(componentId, created);
    return created;
  };
  const add = (
    references: FindingReference[],
    key: keyof Pick<
      ComponentLifecycleSummary,
      | 'newFindings'
      | 'resolvedFindings'
      | 'unchangedFindings'
      | 'reappearedFindings'
      | 'severityChanges'
      | 'dispositionChanges'
    >,
  ) => {
    for (const item of references)
      for (const componentId of item.componentIds?.length ? item.componentIds : [null])
        summary(componentId)[key]++;
  };
  add(groups.newFindings, 'newFindings');
  add(groups.resolvedFindings, 'resolvedFindings');
  add(groups.unchangedFindings, 'unchangedFindings');
  add(groups.reappearedFindings, 'reappearedFindings');
  add(
    groups.severityChanges.map((change) => change.finding),
    'severityChanges',
  );
  add(
    groups.dispositionChanges.map((change) => change.finding),
    'dispositionChanges',
  );
  return [...summaries.values()].sort(
    (left, right) =>
      Number(left.componentId === null) - Number(right.componentId === null) ||
      left.name.localeCompare(right.name),
  );
}

export function compareReports(
  base: AuditReport,
  current: AuditReport,
  history: AuditReport[] = [],
): AuditComparison {
  const baseComponents = componentResolver(base);
  const currentComponents = componentResolver(current);
  const previous = new Map(base.findings.map((finding) => [finding.fingerprint, finding]));
  const latest = new Map(current.findings.map((finding) => [finding.fingerprint, finding]));
  const newFindings = current.findings.filter((finding) => !previous.has(finding.fingerprint));
  const resolvedFindings = base.findings.filter((finding) => !latest.has(finding.fingerprint));
  const unchangedFindings = current.findings.filter((finding) => previous.has(finding.fingerprint));
  const severityChanges = unchangedFindings.flatMap((finding) => {
    const before = previous.get(finding.fingerprint)?.severity;
    return before && before !== finding.severity
      ? [{ finding: reference(finding, currentComponents), before, after: finding.severity }]
      : [];
  });
  const dispositionChanges = unchangedFindings.flatMap((finding) => {
    const before = previous.get(finding.fingerprint)?.disposition;
    return before && before !== finding.disposition
      ? [{ finding: reference(finding, currentComponents), before, after: finding.disposition }]
      : [];
  });
  const componentChanges = unchangedFindings.flatMap((finding) => {
    const beforeFinding = previous.get(finding.fingerprint);
    if (!beforeFinding) return [];
    const before = baseComponents(beforeFinding);
    const after = currentComponents(finding);
    return before.join('\u0000') === after.join('\u0000')
      ? []
      : [{ finding: reference(finding, currentComponents), before, after }];
  });
  const historicalReports = [
    ...new Map(
      history
        .filter((report) => report.auditId !== base.auditId && report.auditId !== current.auditId)
        .map((report) => [report.auditId, report]),
    ).values(),
  ];
  const historicalFingerprints = new Set(
    historicalReports.flatMap((report) => report.findings.map((finding) => finding.fingerprint)),
  );
  const references = {
    newFindings: newFindings.map((finding) => reference(finding, currentComponents)),
    resolvedFindings: resolvedFindings.map((finding) => reference(finding, baseComponents)),
    unchangedFindings: unchangedFindings.map((finding) => reference(finding, currentComponents)),
    reappearedFindings: newFindings
      .filter((finding) => historicalFingerprints.has(finding.fingerprint))
      .map((finding) => reference(finding, currentComponents)),
    severityChanges,
    dispositionChanges,
  };
  return {
    schemaVersion: 2,
    baseAuditId: base.auditId,
    currentAuditId: current.auditId,
    historyReports: historicalReports.length,
    ...references,
    componentChanges,
    components: componentSummaries([base, current, ...historicalReports], references),
    limitations: [
      'Finding lifecycle uses stable fingerprints; line-sensitive moves can appear as one resolved and one new finding.',
      'Resolved means absent from the current report, not proof that the underlying risk was remediated.',
      'Reappeared requires the same fingerprint in an explicitly supplied earlier report and absence from the selected base.',
      'A finding with evidence in multiple components contributes to each component summary.',
    ],
  };
}
