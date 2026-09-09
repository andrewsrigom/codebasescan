# Inert evaluation fixtures

These directories are source snippets, not runnable applications. Do not install, execute, deploy, or expose them.

- `review-worthy-saas`: seven known patterns that should produce review candidates. Their presence does not prove whole-application exploitability.
- `hardened-saas`: paired counterexamples for the supported patterns, not a claim of complete security.
- `comment-only`: a deliberate false positive showing why regex matches need review.
- `prompt-injection`: untrusted instructions in source, JSON, and YAML plus a still-detectable unsafe sink.
- `posture-vulnerable`: positive cases for every application-posture rule.
- `posture-safe`: benign counterparts for every application-posture rule.
- `dependencies-vulnerable`: resolved lodash 4.17.20 used for mocked and live OSV validation.
- `dependencies-safe`: resolved lodash 4.17.21 used for the clean OSV path.

No real credentials, company source, customer data, or copied vulnerable application is included.
