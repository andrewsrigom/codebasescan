# Contributing

CodebaseScan welcomes focused fixes, rules, fixtures, documentation, and usability improvements.

## Setup

Use Node.js 22.16+ on WSL2/Linux:

```bash
npm ci
cp .env.example .env.local
npm run demo
npm run dev
```

Run the worker in a second terminal when testing queued audits:

```bash
npm run worker
```

## Before changing code

- Read [AGENTS.md](AGENTS.md) and the [threat model](docs/THREAT_MODEL.md).
- Never add target-repository execution, arbitrary model tools, or silent cloud fallback.
- Keep code, docs, and UI in English.
- Do not commit real secrets, proprietary source, local databases, reports, model weights, or scanner binaries.

New detection rules need:

- one inert positive fixture;
- one benign counterexample;
- deterministic evidence and an explicit limitation;
- benchmark ground truth when the rule changes measured output.

Do not tune away intentional false-positive fixtures just to improve the score.

## Checks

```bash
npm run format:check
npm run typecheck
npm run lint
npm test
npm run test:graph
npm run benchmark
npm run build
npm run test:e2e
```

If a check cannot run, state why in the pull request.

## Pull requests

Keep changes reviewable and commits focused. Explain:

- user impact;
- security or trust-boundary impact;
- checks actually run;
- remaining gaps.

Large architecture changes need a short entry in [Engineering decisions](docs/DECISIONS.md).

By contributing, you confirm that you can license the change under MIT. Do not copy incompatible third-party scanner rules into configs.
