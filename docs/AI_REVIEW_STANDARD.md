# Structured AI review standard

AI in Traceward is a bounded reviewer of deterministic evidence. It is not an autonomous scanner,
security authority, or source of verified findings. Repository text, filenames, comments, and
scanner output are untrusted data and never instructions.

## Selection and priority

Findings are enriched and sorted deterministically before AI is considered. Priority is clamped to
0–100 and currently uses:

`priority = severity + exposure + detector confidence + dependency evidence + source scope`

- severity: critical 95, high 78, medium 52, low 28, info 10;
- exposure: potentially public +10, authenticated +4, local -8, unknown 0;
- detector confidence: high +5, medium 0, low -10;
- dependency evidence: source referenced +7, direct but not referenced -2, other advisory -18;
- finding evidence entirely in tests/examples: -15.

The queue is sorted by priority and stable finding ID. Secret findings bypass model inference. The
current finding workflow inspects at most 12 non-secret candidates per audit. AI does not roam the
repository looking for additional problems.

## Context protocol

The context broker exposes only opaque IDs related to the selected finding: evidence, entry points,
symbols, security facts, and resolved calls. A model cannot request an arbitrary path.

- at most 60 catalog entries;
- at most 12 initial entries;
- at most 2 requested IDs per round;
- at most 2 context rounds;
- at most 6,000 characters per item and 16,000 total characters;
- every delivery is resolved against the immutable captured snapshot and redacted again.

Unknown, duplicate, path-shaped, excessive, or unavailable requests are rejected. Secret files do
not enter the snapshot.

## Required review checklist

For one deterministic finding, the reviewer must:

1. identify the request boundary or source condition represented by supplied IDs;
2. list controls directly visible in supplied evidence;
3. list the exact evidence still missing;
4. state impact and required preconditions without claiming exploitability;
5. give bounded remediation choices, including trade-offs when relevant;
6. give safe verification steps that could falsify the assessment;
7. state static, runtime, infrastructure, and context limitations.

The response must validate against the versioned structured schema and include:

- `assessment`: `likely_issue`, `likely_false_positive`, or `inconclusive`;
- `confidence`, `explanation`, and cited `evidenceIds`;
- `controlsFound`, `missingEvidence`, `impact`, and `preconditions`;
- `remediationOptions` and `verificationPlan`;
- `limitations` and optional bounded `requestedContextIds`;
- provider, model, prompt version, delivered context IDs/files, rounds, truncation, redaction, token,
  cache, latency, and configured-cost provenance where available.

An invalid schema or citation fails closed and preserves the original finding. AI cannot lower
scanner severity, suppress evidence, set a human disposition, mark a task fixed, or certify
coverage.

## Correction boundary

Assessment and correction are separate operations. A coding agent may modify a project only after
separate authorization and must consume one versioned task bundle, stay inside allowed paths, make
one coherent change, run only authorized commands, and require a fresh Traceward audit to show that
the candidate disappeared. Authentication policy, tenant model, billing behavior, database
migrations, destructive actions, and deployment always require human authorization.

Task-bundle version 3 supplies the owning workspace component, adjacent cross-component import
edges, and any matching security-critical test-reference target. These records help the coding
agent select local context and focused tests; they do not claim that a test executed or asserted the
reported behavior.

API contract differences may be used as bounded supporting context, but remain mechanical
documentation candidates. AI must not relabel a declared-only or source-only record as a deployed
security vulnerability without separately cited source and runtime evidence.

Database contract differences are also bounded supporting context only. AI must preserve missing
schema, migration, and runtime evidence as unknown and may not recommend executing a migration as
part of review.

## Expansion gate

Checklist-gap investigation and whole-report synthesis remain future workflows. They may be enabled
only after they use the same bounded ID protocol and structured result contract, have mocked failure
and budget tests, and demonstrate better accepted-review value on authorized projects. Provider
comparison must record invalid citations, abstention, latency, tokens, cost, and accepted outcomes;
fixture success alone is insufficient.
