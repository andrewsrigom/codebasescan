# Deterministic example exports

Regenerate with:

```bash
npm run example
```

This command runs the deterministic scanner and manifest inventory against `fixtures/review-worthy-saas`, then emits JSON, Markdown, HTML, and SARIF. It does not invoke external scanners.

Open `fixture-review.html` directly to inspect a self-contained report without installing application dependencies. The other files expose the structured report model and interchange formats. The stable timestamp/UUID identify a reproducible example, not an actual queued audit.

All source is deliberately inert fixture content. The seven findings are review candidates, not verified exploitable vulnerabilities. Keep these qualifications when reusing the reports in a demonstration.
