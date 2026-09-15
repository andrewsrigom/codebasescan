# CodebaseScan agent contract

## Required artifacts

- `agent-context.json`: observed application signals, declared context, unresolved questions, and coverage warnings.
- `agent-report.json`: workflow, review depths, prioritized tasks, and rule guidance.
- `audit-report.json`: immutable deterministic findings and captured evidence.
- `run-manifest.json`: executed scanner coverage, limitations, artifact paths, and SHA-256 hashes.
- `agent-rules.json`: versioned review questions, required evidence, risk signals, safe signals, and false-positive checks.

The JSON Schema files beside these artifacts define the machine-readable contracts.

Read context as claims with different strength. An observed cookie operation does not prove that a
request authenticates with cookies; a `postMessage` call does not prove which deployed application
is the parent; and a missing source declaration does not prove a missing proxy or CDN control.

## Evidence model

Keep these layers distinct:

1. **Deterministic evidence**: source or package facts captured by CodebaseScan.
2. **Deterministic candidate**: a rule result supported by that evidence.
3. **Agent assessment**: a conclusion reached after inspecting relevant repository context.
4. **Hypothesis**: a lead that still lacks enough evidence.
5. **Human disposition**: confirmed, false positive, or accepted risk recorded outside the scanner result.

Only the first two layers belong to the original audit. An agent may enrich them but cannot rewrite them.

## Depths

### Quick

Use existing report evidence. Rank, group, and explain. Avoid broad repository searches.

### Standard

Inspect the reported location, direct callers, related configuration, and rule-specific false-positive checks. Search narrowly for evidence required by the task.

### Deep

Trace data and control flow across relevant files. Compare implementations against the complete rule pack and identify missing-control candidates. Keep newly discovered candidates separate and label uncertainty.

## Output

For each reviewed issue include:

- status: confirmed, likely, inconclusive, or false positive;
- affected behavior and practical impact;
- evidence with file and line citations;
- false-positive checks performed;
- remaining uncertainty;
- next safe verification step.

Finish with coverage limits from the run manifest and a separate list of newly discovered candidates.
