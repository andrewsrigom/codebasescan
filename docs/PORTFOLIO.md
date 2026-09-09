# Portfolio plan

## The story

“I built a local-first security review workbench that separates deterministic scanner signals, bounded LLM assessments, and human decisions. I used LangGraph for stateful orchestration and made incomplete coverage explicit instead of claiming every result was a verified vulnerability.”

Only add measured reliability, model performance, or production usage claims once there is supporting evidence.

## Demonstration sequence

1. Open the included review-worthy SaaS audit. Show seven candidates and the disabled external scanner badges.
2. Inspect the raw-SQL candidate: rule, file, snapshot digest, excerpt, caveats, remediation. Explain why pattern matching is not proof of exploitability.
3. Open the dependency tab and say exactly what is known: manifest requirements, not resolved vulnerable packages.
4. Scan the comment-only fixture. Show that a heuristic can flag a comment. Record a human false-positive disposition with a rationale rather than letting AI silently hide it.
5. Inspect the workflow: scanner fan-out/fan-in, bounded investigation, publication interrupt. Submit publication and let the separate worker resume the same audit.
6. Export self-contained HTML and SARIF. Show that unresolved findings and coverage caveats travel with the report.
7. In a later validated demonstration, enable one real scanner and one local model, record versions/hardware, and compare the assessment with the deterministic baseline.

## What an interviewer can inspect

| Engineering skill | Evidence in the repository |
| --- | --- |
| Frontend product work | Audit navigation, findings filters, readable evidence, keyboard dialogs, responsive UI |
| Backend architecture | Persistent queue, process isolation from Next, transactions, cancellation, review transitions |
| Agent engineering | State/reducers, conditional bounded loops, source tool, structured output, durable interrupts |
| Security judgment | Threat model, limited privileges, real statuses, best-effort redaction, no false certainty |
| Testing discipline | Positive and benign fixtures, intentional false positive, core and integration suites, explicit validation gaps |
| Product prioritization | Narrow scope, no premature billing/cloud/multi-agent infrastructure |

## Before making the repository public

- Complete the full validation gate; capture real app screenshots and a short actual demonstration.
- Remove local DBs, exports from real repositories, `.env.local`, logs, credentials, and personal paths.
- Verify the working name and ownership/license metadata. Audit dependencies and trusted scanner distribution rules.
- Enable a private vulnerability-reporting channel and publish supported versions and limitations.
- Keep setup simple. A reviewer should reach a labeled demonstration without providing a paid API key.
- Use an honest README status badge from real CI only. Stars, downloads, accuracy, and customer counts must never be fabricated.

## Useful first public issue

“Replace one regex authorization heuristic with a narrow AST-aware detector and prove its behavior against explicit-middleware and RLS counterexamples.” This is more credible than a promise to audit every language or detect every vulnerability.

## Demo assets

Any bundled static styling preview is labeled as such. It does not establish that Next.js hydration, graph persistence, or E2E behavior passed. The generated HTML report can be previewed independently of the app. Replace preview imagery with verified runtime screenshots after P0.
