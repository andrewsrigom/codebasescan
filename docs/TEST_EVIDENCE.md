# Security-critical test evidence

Traceward maps captured test imports to security-relevant source files without loading project
configuration or executing the audited repository. The result is written to `test-evidence.json`
and embedded in the audit report and investigation bundle.

## Deterministic method

Let `E` be files containing a mapped request entry point and `S` be files containing a project fact
classified as database, billing, raw SQL, command execution, or file access. The bounded critical
set is:

`C = unique(E union S)`

Traceward parses captured JavaScript and TypeScript imports as data and constructs a directed graph
`G(file -> resolved captured file)`. For each captured test file `t` and critical file `c`, related
evidence is observed when a path exists in `G`:

`related(t, c) = shortest_path(G, t, c), depth <= 5`

Depth 1 is a direct import. Depth 2–5 is a transitive import. Up to 500 critical targets and 20 test
references per target are retained. Counts, truncation, parse failures, and unresolved local imports
remain explicit.

## Meaning of the states

- `observed`: at least one captured test imports the critical file directly or through resolved
  captured source.
- `not-observed`: no such import path was found.
- `partial`: parsing, resolution, snapshot, or retention limits prevent complete relationship data.
- `unsupported`: no supported critical source target was mapped.

An observed import does not prove that the test asserts authentication, authorization, tenant
isolation, billing integrity, or any other security behavior. `not-observed` does not prove that the
file is untested. URL-only browser tests, generated registration, dynamic imports, unsupported
aliases, external test harnesses, and runtime coverage can escape this source relationship.

## Consumer rule

Humans and agents may use this artifact to prioritize verification work. They must not turn it into
a vulnerability, test-coverage percentage, or release pass/fail result without stronger evidence.
Any proposed test must cite the target, the relevant entry point or sensitive fact IDs, and the
specific behavior it intends to verify.
