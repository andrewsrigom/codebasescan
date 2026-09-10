# Webhook contract correlation

Traceward maps captured HTTP webhook endpoints to bounded call relationships, signature-verification
facts, idempotency facts, and literal event names. TypeScript and JavaScript are parsed as inert
syntax. Target modules, handlers, configurations, and provider SDKs are never imported or executed.

## Endpoint selection

Next.js App Router, Pages Router, and Express routes are eligible when their mapped route, file, or
entry-point name contains webhook or hook. A callback route is included only when its bounded call
graph reaches captured webhook-verification evidence, avoiding ordinary OAuth callbacks.

Each endpoint retains its entry-point ID, owning component, methods, reachable symbol IDs, traversed
call-edge IDs, related event-reference IDs, and exact verification/idempotency fact IDs. Traversal is
limited to eight resolved call edges deep, 1,000 symbols, and 5,000 call edges per endpoint.

## Event vocabulary

The scanner records literal names from:

- switch cases and equality branches on type, event, eventType, or topic properties;
- literal type/event fields returned by webhook-reachable adapter functions;
- literal type/event payloads passed to recognized send, emit, publish, dispatch, deliver, trigger,
  enqueue, or webhook call chains.

A name produced and consumed in captured local source is `matched-local`. A name visible on only one
side is an `external-consumer-boundary` or `external-producer-boundary`, not a defect: its other side
may be a payment provider, source-control service, or customer endpoint.

## Evidence meaning

`evidenced` means the bounded source relationship reaches a fact already captured by the project
profiler. `unverified` means that Traceward did not capture that relationship. It does not prove the
runtime control is absent, correct, or effective. Dynamic dispatch, generated handlers, provider
configuration, replay windows, database constraints, queues, and runtime behavior remain outside
this static result.

Coverage becomes partial when the snapshot/profile is partial, parsing fails, or traversal/output
bounds are reached. With no eligible endpoint it is unsupported rather than clean. Full structured
output is `webhook-contract.json` and is also included in the investigation bundle.
