# Preview assets

`workspace-styling-preview.png` is a static inspection of the authored JSX/CSS with inert example data. It carries a visible styling-preview banner. A small temporary serializer replaced framework hooks solely to inspect layout; this was not a Next.js runtime, React hydration, live audit, or integration test. That serializer is not part of the shipped application.

`html-report-preview.png` shows the real self-contained HTML emitted by `npm run example`, rendered in Chromium. The example is produced by the deterministic core only. No graph, external scanner, or LLM execution is implied.

Replace the workspace preview with real application screenshots after the complete release validation gate. Never remove the distinction between simulated presentation and observed runtime behavior.
