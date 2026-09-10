import { parseDocument } from 'yaml';
import { makeFinding, sourceEvidence } from '../domain/findings.ts';
import type {
  Finding,
  ScannerRun,
  Snapshot,
  SourceFile,
  SupplyChainAnalysis,
} from '../domain/types.ts';
import { isRuntimeSource } from '../security/paths.ts';

type IssueCount = keyof SupplyChainAnalysis['issueCounts'];

interface Candidate {
  count: IssueCount;
  ruleId: string;
  title: string;
  severity: Finding['severity'];
  description: string;
  remediation: string;
  cwe: string[];
  file: SourceFile;
  line: number;
  observation: string;
}

interface Manifest {
  file: SourceFile;
  dependencies: Map<string, string>;
  scripts: Record<string, string>;
}

const lifecycleNames = new Set(['preinstall', 'install', 'postinstall', 'prepare']);
const dangerousLifecycle =
  /(?:curl|wget)\b[^\n|]{0,500}\|\s*(?:sh|bash|zsh)\b|powershell(?:\.exe)?\b[^\n]{0,500}(?:-enc(?:odedcommand)?\b|downloadstring|invoke-webrequest|start-bitstransfer)|\b(?:eval|invoke-expression)\b|\bchmod\s+\+x\b[^\n;&|]{0,300}(?:[;&|]|&&)\s*(?:\.\/|sh\b|bash\b)/i;
const commitHash = /^[0-9a-f]{40}$/i;
const lockNames = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'pnpm-lock.yaml',
  'yarn.lock',
]);
const expectedRegistryHosts = new Set(['registry.npmjs.org', 'registry.yarnpkg.com']);

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function lineOf(file: SourceFile, needle: string): number {
  const index = file.content.indexOf(needle);
  return index < 0 ? 1 : file.content.slice(0, index).split('\n').length;
}

function manifestFiles(snapshot: Snapshot): Manifest[] {
  const manifests: Manifest[] = [];
  for (const file of snapshot.files.filter(
    (item) => isRuntimeSource(item) && item.path.split('/').at(-1) === 'package.json',
  )) {
    try {
      const root = object(JSON.parse(file.content));
      if (!root) continue;
      const dependencies = new Map<string, string>();
      for (const key of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
        const section = object(root[key]);
        if (!section) continue;
        for (const [name, value] of Object.entries(section))
          if (typeof value === 'string') dependencies.set(name, value);
      }
      const rawScripts = object(root.scripts) ?? {};
      const scripts = Object.fromEntries(
        Object.entries(rawScripts).filter(
          (entry): entry is [string, string] => typeof entry[1] === 'string',
        ),
      );
      manifests.push({ file, dependencies, scripts });
    } catch {
      // Malformed manifests are already reported by the dependency inventory.
    }
  }
  return manifests;
}

function unsafeDependencySpec(spec: string): string | null {
  const value = spec.trim();
  if (/^https?:\/\//i.test(value))
    return value.toLowerCase().startsWith('http://')
      ? 'Dependency is downloaded over plaintext HTTP.'
      : null;
  if (/^(?:file|link):/i.test(value)) {
    const target = value.slice(value.indexOf(':') + 1);
    if (/^(?:\/|\\|[a-z]:)/i.test(target) || target.split(/[\\/]/).includes('..'))
      return 'Dependency uses a machine-relative or parent-traversing local path.';
    return null;
  }
  const gitLike = /^(?:git(?:\+[^:]+)?:|github:|gitlab:|bitbucket:)|^[\w.-]+\/[\w.-]+(?:#.*)?$/i;
  if (!gitLike.test(value)) return null;
  const fragment = value.includes('#')
    ? (value.slice(value.lastIndexOf('#') + 1).split('&')[0] ?? '')
    : '';
  return commitHash.test(fragment) ? null : 'Git dependency is not pinned to a full commit hash.';
}

function candidateFinding(candidate: Candidate): Finding {
  const evidence = sourceEvidence(candidate.file, candidate.line, candidate.observation);
  evidence.kind = 'declared';
  return makeFinding({
    source: 'supply-chain',
    ruleId: candidate.ruleId,
    title: candidate.title,
    category: 'dependencies',
    severity: candidate.severity,
    sourceSeverity: candidate.severity,
    description: candidate.description,
    remediation: candidate.remediation,
    cwe: candidate.cwe,
    evidence: [evidence],
    confidence: candidate.severity === 'low' ? 'medium' : 'high',
  });
}

function manifestCandidates(manifests: Manifest[]): Candidate[] {
  const candidates: Candidate[] = [];
  for (const manifest of manifests) {
    for (const [name, command] of Object.entries(manifest.scripts)) {
      if (!lifecycleNames.has(name) || !dangerousLifecycle.test(command)) continue;
      candidates.push({
        count: 'dangerousLifecycleScripts',
        ruleId: 'TW-SC001',
        title: 'Package lifecycle script performs a high-risk shell action',
        severity: 'high',
        description: `The ${name} script contains a download-and-execute, dynamic evaluation, or permission-and-execute pattern. CodebaseScan inspected the declaration and did not run it.`,
        remediation:
          'Remove the network or dynamic execution step, pin and verify any downloaded artifact, and keep installation deterministic. Review the publisher and exact script before installing dependencies.',
        cwe: ['CWE-494', 'CWE-829'],
        file: manifest.file,
        line: lineOf(manifest.file, `"${name}"`),
        observation: `High-risk command pattern declared in the ${name} lifecycle script; it was not executed.`,
      });
    }
    for (const [name, spec] of manifest.dependencies) {
      const reason = unsafeDependencySpec(spec);
      if (!reason) continue;
      candidates.push({
        count: 'unsafeDependencySpecs',
        ruleId: 'TW-SC002',
        title: 'Dependency source is not safely reproducible',
        severity: spec.toLowerCase().startsWith('http://') ? 'high' : 'medium',
        description: `${name} is declared as ${spec}. ${reason}`,
        remediation:
          'Use an HTTPS registry package with a reviewed lockfile, or pin a Git dependency to a full commit hash. Avoid absolute and parent-relative local dependencies in distributable applications.',
        cwe: ['CWE-494', 'CWE-829'],
        file: manifest.file,
        line: lineOf(manifest.file, `"${name}"`),
        observation: `${name} uses dependency specifier ${spec}.`,
      });
    }
  }
  return candidates;
}

function lockEntryCandidates(file: SourceFile): { candidates: Candidate[]; entries: number } {
  const candidates: Candidate[] = [];
  let entries = 0;
  const inspect = (label: string, entry: Record<string, unknown>) => {
    if (entry.link === true || entry.inBundle === true) return;
    const resolved =
      typeof entry.resolved === 'string'
        ? entry.resolved
        : typeof entry.tarball === 'string'
          ? entry.tarball
          : '';
    const integrity =
      typeof entry.integrity === 'string'
        ? entry.integrity
        : typeof entry.checksum === 'string'
          ? entry.checksum
          : '';
    const pinnedCommit = typeof entry.commit === 'string' && commitHash.test(entry.commit);
    if (
      typeof entry.version !== 'string' &&
      typeof entry.resolution !== 'string' &&
      !resolved &&
      !integrity &&
      !pinnedCommit
    )
      return;
    entries++;
    if (resolved && /^http:\/\//i.test(resolved)) {
      candidates.push({
        count: 'insecureLockfileUrls',
        ruleId: 'TW-SC003',
        title: 'Lockfile downloads a package over plaintext HTTP',
        severity: 'high',
        description: `${label} resolves through an unencrypted URL, allowing the package payload to be replaced in transit.`,
        remediation:
          'Regenerate the lockfile from a trusted HTTPS registry and verify package integrity.',
        cwe: ['CWE-494'],
        file,
        line: lineOf(file, resolved),
        observation: `Plaintext package URL: ${resolved.slice(0, 500)}`,
      });
    } else if (resolved && /^https:\/\//i.test(resolved)) {
      try {
        const host = new URL(resolved).hostname.toLowerCase();
        if (!expectedRegistryHosts.has(host))
          candidates.push({
            count: 'unexpectedLockfileHosts',
            ruleId: 'TW-SC004',
            title: 'Lockfile uses a non-default package host',
            severity: 'low',
            description: `${label} resolves from ${host}. This can be intentional for a private registry, but the host belongs in the repository trust review.`,
            remediation:
              'Confirm the host is an approved registry, requires HTTPS, and is protected against dependency-confusion and namespace takeover.',
            cwe: ['CWE-829'],
            file,
            line: lineOf(file, resolved),
            observation: `Package payload host is ${host}, outside the built-in npm/Yarn registry allowlist.`,
          });
      } catch {
        // Invalid URLs are ignored here; package managers will reject them separately.
      }
    }
    if (
      (!integrity || /^sha1-/i.test(integrity)) &&
      !pinnedCommit &&
      !/^(?:file|link|workspace):/i.test(resolved)
    )
      candidates.push({
        count: 'weakLockfileIntegrity',
        ruleId: 'TW-SC005',
        title: integrity
          ? 'Lockfile uses weak SHA-1 package integrity'
          : 'Lockfile entry has no package integrity',
        severity: integrity ? 'medium' : 'low',
        description: `${label} ${integrity ? 'uses SHA-1' : 'has no captured integrity digest'}. Older lockfile formats and private registries may explain this, so it remains a review candidate.`,
        remediation:
          'Regenerate the lockfile with a current package manager and trusted registry so remote packages have SHA-512 integrity metadata.',
        cwe: ['CWE-353'],
        file,
        line: lineOf(file, label),
        observation: integrity
          ? `Integrity uses ${integrity.split('-')[0]}.`
          : 'No integrity or checksum field was found for this lock entry.',
      });
  };

  try {
    if (file.path.endsWith('.json')) {
      const root = object(JSON.parse(file.content));
      const packages = object(root?.packages);
      if (packages)
        for (const [label, raw] of Object.entries(packages)) {
          if (!label) continue;
          const entry = object(raw);
          if (entry) inspect(label, entry);
        }
      else {
        const walk = (tree: Record<string, unknown>) => {
          for (const [label, raw] of Object.entries(tree)) {
            const entry = object(raw);
            if (!entry) continue;
            inspect(label, entry);
            const nested = object(entry.dependencies);
            if (nested) walk(nested);
          }
        };
        const dependencies = object(root?.dependencies);
        if (dependencies) walk(dependencies);
      }
    } else if (file.path.endsWith('pnpm-lock.yaml')) {
      const document = parseDocument(file.content, { schema: 'core' });
      if (document.errors.length) return { candidates, entries };
      const root = object(document.toJS({ maxAliasCount: 20 }));
      const packages = object(root?.packages);
      if (packages)
        for (const [label, raw] of Object.entries(packages)) {
          const entry = object(raw);
          if (!entry) continue;
          const resolution = object(entry.resolution);
          inspect(label, resolution ? { ...entry, ...resolution } : entry);
        }
    } else if (file.content.trimStart().startsWith('__metadata:')) {
      const document = parseDocument(file.content, { schema: 'core' });
      if (document.errors.length) return { candidates, entries };
      const root = object(document.toJS({ maxAliasCount: 20 }));
      if (root)
        for (const [label, raw] of Object.entries(root)) {
          if (label === '__metadata') continue;
          const entry = object(raw);
          if (entry) inspect(label, entry);
        }
    } else {
      let label = '';
      let entry: Record<string, unknown> = {};
      const flush = () => {
        if (label) inspect(label, entry);
      };
      for (const line of file.content.split(/\r?\n/)) {
        if (/^\S.*:\s*$/.test(line) && !line.startsWith('#')) {
          flush();
          label = line.slice(0, line.lastIndexOf(':')).replace(/^"|"$/g, '');
          entry = {};
          continue;
        }
        const field = /^\s+(version|resolved|integrity)\s+["']?([^"']+)["']?\s*$/.exec(line);
        if (field?.[1] && field[2]) entry[field[1]] = field[2];
      }
      flush();
    }
  } catch {
    // Parse failures are exposed by the dependency inventory scanner.
  }
  return { candidates, entries };
}

function manifestLockCandidates(manifests: Manifest[], lockfiles: SourceFile[]): Candidate[] {
  const candidates: Candidate[] = [];
  for (const manifest of manifests) {
    const directory = manifest.file.path.includes('/')
      ? manifest.file.path.slice(0, manifest.file.path.lastIndexOf('/'))
      : '';
    const lock = lockfiles.find((file) => {
      const lockDirectory = file.path.includes('/')
        ? file.path.slice(0, file.path.lastIndexOf('/'))
        : '';
      return lockDirectory === directory && file.path.endsWith('package-lock.json');
    });
    if (!lock) continue;
    try {
      const root = object(JSON.parse(lock.content));
      const lockedRoot = object(object(root?.packages)?.['']) ?? root;
      const locked = new Map<string, string>();
      for (const key of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
        const section = object(lockedRoot?.[key]);
        if (!section) continue;
        for (const [name, spec] of Object.entries(section))
          if (typeof spec === 'string') locked.set(name, spec);
      }
      for (const [name, spec] of manifest.dependencies) {
        const lockSpec = locked.get(name);
        if (lockSpec === spec) continue;
        candidates.push({
          count: 'manifestLockMismatches',
          ruleId: 'TW-SC006',
          title: 'Package manifest and npm lockfile are out of sync',
          severity: 'medium',
          description:
            lockSpec === undefined
              ? `${name} is declared in ${manifest.file.path} but absent from the matching npm lockfile root.`
              : `${name} requests ${spec} in the manifest but ${lockSpec} in the matching npm lockfile root.`,
          remediation:
            'Regenerate and commit the lockfile with the repository package manager, then review the resulting dependency diff.',
          cwe: ['CWE-1104'],
          file: manifest.file,
          line: lineOf(manifest.file, `"${name}"`),
          observation:
            lockSpec === undefined
              ? `${name} is missing from the lockfile root declarations.`
              : `Manifest spec ${spec} differs from lockfile root spec ${lockSpec}.`,
        });
      }
    } catch {
      // Parse failures are exposed by the dependency inventory scanner.
    }
  }
  return candidates;
}

export interface SupplyChainResult {
  findings: Finding[];
  analysis: SupplyChainAnalysis;
  run: ScannerRun;
}

export function scanSupplyChain(snapshot: Snapshot): SupplyChainResult {
  const started = performance.now();
  const manifests = manifestFiles(snapshot);
  const lockfiles = snapshot.files.filter(
    (file) => isRuntimeSource(file) && lockNames.has(file.path.split('/').at(-1) ?? ''),
  );
  const candidates = manifestCandidates(manifests);
  let lockEntries = 0;
  for (const file of lockfiles) {
    const result = lockEntryCandidates(file);
    lockEntries += result.entries;
    candidates.push(...result.candidates);
  }
  candidates.push(...manifestLockCandidates(manifests, lockfiles));
  const unique = new Map<string, Candidate>();
  for (const candidate of candidates)
    unique.set(
      `${candidate.ruleId}:${candidate.file.path}:${candidate.line}:${candidate.observation}`,
      candidate,
    );
  const bounded = [...unique.values()].slice(0, 500);
  const findings = bounded.map(candidateFinding);
  const issueCounts: SupplyChainAnalysis['issueCounts'] = {
    dangerousLifecycleScripts: 0,
    unsafeDependencySpecs: 0,
    weakLockfileIntegrity: 0,
    insecureLockfileUrls: 0,
    unexpectedLockfileHosts: 0,
    manifestLockMismatches: 0,
  };
  for (const candidate of unique.values()) issueCounts[candidate.count]++;
  const truncated = unique.size > bounded.length || snapshot.truncated;
  const lifecycleScripts = manifests.reduce(
    (sum, manifest) =>
      sum + Object.keys(manifest.scripts).filter((name) => lifecycleNames.has(name)).length,
    0,
  );
  const dependencySpecs = manifests.reduce((sum, manifest) => sum + manifest.dependencies.size, 0);
  const analysis: SupplyChainAnalysis = {
    schemaVersion: 1,
    manifests: manifests.length,
    lockfiles: lockfiles.length,
    lifecycleScripts,
    dependencySpecs,
    lockEntries,
    issueCounts,
    truncated,
  };
  return {
    findings,
    analysis,
    run: {
      id: 'supply-chain',
      name: 'Node.js supply-chain integrity',
      status: truncated ? 'partial' : manifests.length ? 'completed' : 'skipped',
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      findings: findings.length,
      detail: manifests.length
        ? `Inspected ${manifests.length} manifest(s), ${lockfiles.length} lockfile(s), ${dependencySpecs} dependency specifier(s), and ${lockEntries} resolved lock entry(s) without installing packages.`
        : 'No runtime package.json manifest was captured.',
      version: '0.1.0',
    },
  };
}
