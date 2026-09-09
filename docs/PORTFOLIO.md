# Portfolio plan

## The story

“I built a local-first security review workbench that separates deterministic scanner signals, bounded LLM assessments, and human decisions. I used LangGraph for stateful orchestration and made incomplete coverage explicit instead of claiming every result was a verified vulnerability.”

Only add measured reliability, model performance, or production usage claims once there is supporting evidence.

## Demonstration sequence

1. Open the included review-worthy SaaS audit. Show deterministic candidates and explicit capability status.
2. Inspect the raw-SQL candidate: rule, file, snapshot digest, excerpt, caveats, remediation. Explain why pattern matching is not proof of exploitability.
3. Open the dependency tab. Show requested versus resolved versions, direct/transitive relationship, OSV aliases/fixes, and the explicit lack of reachability proof.
4. Scan the comment-only fixture. Show that a heuristic can flag a comment. Record a human false-positive disposition with a rationale rather than letting AI silently hide it.
5. Inspect the workflow: scanner fan-out/fan-in, bounded investigation, publication interrupt. Submit publication and let the separate worker resume the same audit.
6. Approve a localhost HTTP target. Show declared versus observed header evidence and explain why one response is not whole-app coverage.
7. Export self-contained HTML and SARIF, run the CI severity gate, and compare two local audits.
8. Show the benchmark output: 9 TP, 1 intentional FP, 0 FN, precision 0.9, recall 1.0 on the declared narrow dataset. Explicitly reject general accuracy claims.
9. In a later demonstration, validate one OpenAI and one Ollama model, record versions/hardware/tokens/cost, and compare contextual assessments with the deterministic baseline.

## What an interviewer can inspect

| Engineering skill      | Evidence in the repository                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------ |
| Frontend product work  | Audit navigation, findings filters, readable evidence, keyboard dialogs, responsive UI                       |
| Backend architecture   | Persistent queue, process isolation from Next, transactions, cancellation, review transitions                |
| Agent engineering      | State/reducers, conditional bounded loops, source tool, structured output, durable interrupts                |
| Security judgment      | Threat model, limited privileges, real statuses, best-effort redaction, no false certainty                   |
| Testing discipline     | Paired posture fixtures, HTTP/OSV/OpenAI mocks, real scanner tests, prompt injection, ground-truth benchmark |
| Product prioritization | Narrow scope, no premature billing/cloud/multi-agent infrastructure                                          |

## Before making the repository public

- Complete the full validation gate; capture real app screenshots and a short actual demonstration.
- Remove local DBs, exports from real repositories, `.env.local`, logs, credentials, and personal paths.
- Verify the working name and ownership/license metadata. Audit dependencies and trusted scanner distribution rules.
- Enable a private vulnerability-reporting channel and publish supported versions and limitations.
- Keep setup simple. A reviewer should reach a labeled demonstration without providing a paid API key.
- Use an honest README status badge from real CI only. Stars, downloads, accuracy, and customer counts must never be fabricated.

## Useful next public issue

“Replace one regex authorization heuristic with a narrow AST-aware detector and prove its behavior against explicit-middleware and RLS counterexamples.” This is more credible than a promise to audit every language or detect every vulnerability.

## Demo assets

The existing image began as a static styling preview and should be replaced with a verified current runtime screenshot before public release. The generated HTML report can be previewed independently of the app; it does not replace browser-flow evidence.
