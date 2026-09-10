# API contract consistency

CodebaseScan compares captured OpenAPI or Swagger operations with statically mapped Next.js and
Express route operations. It parses JSON and YAML as inert data. It does not import generators,
resolve external references, start the target application, or execute configuration.

## Inputs

A runtime-scoped JSON, YAML, or YML file is considered when its basename starts with openapi or
swagger, or its content has a root OpenAPI/Swagger version marker. A valid specification must
contain a string version and an object-valued paths map.

Source operations come only from mapped next-route, next-pages-api, and express-route entrypoints
with a statically observed HTTP method. Server Actions, middleware, tRPC procedure names, and
routes without a known method are not converted into URL operations.

## Match rule

Each operation is keyed by uppercase HTTP method plus normalized path. Normalization removes
query/fragment text and trailing slashes, ignores Next.js route groups and parallel-route
segments, and maps OpenAPI {id}, Express :id, and Next.js [id] or catch-all segments to {}.

For each specification, CodebaseScan derives the common static path prefix of its declared operations.
An unmatched source route is source-only only when it falls inside one of those path scopes.
Unmatched routes outside them are retained as outside-contract-scope and are not counted as
differences. This avoids treating a deliberately partial specification as a promise to document
every application route.

The output keeps both sides:

- matched: method and normalized path exist in the declaration and captured source;
- declared-only: no captured source operation matched;
- source-only: no captured declaration matched;
- outside-contract-scope: unmatched source route outside the specification namespace;
- sourceRoutesWithoutMethods: a route exists, but a method was not statically established.

These are documentation-consistency candidates. They do not prove that an endpoint is missing,
reachable, public, undocumented at runtime, or deployed.

## Bounds and coverage

- at most 20 specifications;
- at most 1,000 declared operations;
- at most 2,000 source operations;
- at most 500 route IDs without methods;
- aliases in YAML conversion are bounded;
- local or external path-item references are not resolved.

Coverage is unsupported when no valid captured specification is available, partial after parse
failures, unresolved path references, truncation, or an incomplete source profile, and complete
only when those conditions are absent. Full machine output is api-contract.json.
