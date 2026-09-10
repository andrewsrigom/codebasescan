# Feature flag consistency

Traceward correlates captured feature-flag declarations with literal source evaluation calls. JSON
is parsed as inert data and TypeScript/JavaScript as inert syntax. Target configuration, generated
modules, application code, and provider SDKs are never imported or executed.

## Captured declarations

The deterministic scanner supports:

- primitive values inside JSON `featureFlags` or `feature_flags` maps;
- literal TypeScript definition arrays/objects whose variable name identifies feature flags or flag
  definitions, using literal `key`, `flagKey`, `featureKey`, or `name` fields;
- bounded primitive defaults without retaining arbitrary string values. Every value keeps its type
  and digest; only booleans, numbers, and a small status vocabulary are displayed.

Different values for the same key across declaration files are allowed because plans, environments,
and product variants legitimately differ. They do not become default conflicts by themselves.

## Captured usages

Literal keys are read only from recognized evaluation APIs such as `isFeatureEnabled`,
`evaluateRuntimeFeatureFlag`, `getFeatureFlag`, provider `variation`/gate/value methods, and literal
definition-by-key lookups. Broad helpers that merely contain `flag` in their name are excluded.

Each usage retains file, line, owning component, callee, guard/read context, optional sanitized
default, declaration IDs, and status. Dynamic keys remain separate and visible instead of being
guessed.

## Consistency states

- `matched`: at least one captured declaration and literal usage share the normalized key;
- `declaration-only`: no literal usage was captured;
- `usage-only`: declarations exist, but the literal key has no captured declaration;
- `default-conflict`: source usages disagree on a literal default, or one unambiguous declared
  default differs from one literal source default.

These are consistency candidates, not proof that a feature is dead, unavailable, or misconfigured
at runtime. Remote control planes, database state, generated artifacts, aliases, wrapper data flow,
and dynamic keys may supply the missing side.

Coverage is partial when relevant source cannot be parsed or snapshot/profile/output limits are
reached. A project with no supported declaration, provider, or evaluation call is unsupported rather
than clean. Full machine output is `feature-flags.json` and is included in the investigation bundle.
