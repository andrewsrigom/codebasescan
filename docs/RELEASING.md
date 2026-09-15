# Releasing

CodebaseScan is public on npm. Ordinary branch pushes never publish the package: only an exact
version tag enters the protected trusted-publisher workflow.

## Release candidate gate

From a clean checkout on Linux or WSL with Node 24:

```bash
npm ci
npm run release:check
npm run test:e2e
npm run test:package:pnpm
npm run test:package:yarn
```

Confirm the public GitHub `validate` and `package-smoke` jobs pass. Inspect `npm pack --dry-run`
and one generated report directory for unexpected source excerpts, private paths, or secrets.
Immediately before publishing, confirm the candidate version is not already present on npm.

The `Publish CodebaseScan` workflow can be started manually from GitHub Actions. Manual runs only
execute the release gate and npm dry-run; they cannot enter the publish job.

## Registry setup

Use an npm account with two-factor authentication and recovery codes. Configure npm trusted
publishing for:

- GitHub owner: `andrewsrigom`
- repository: `codebasescan`
- workflow: `publish.yml`
- environment: `npm`

Protect the GitHub `npm` environment with required maintainer approval. Trusted publishing uses
short-lived OIDC credentials and automatically attaches provenance for a public package built from
this public repository. No long-lived npm token belongs in the repository.

## Publish

Only after the release candidate is green:

1. update the changelog and Action's exact npm version, then commit the candidate;
2. run `npm run release:check` and confirm the public CI matrix and manual dry-run are green;
3. create and push the exact tag `v<package-version>`;
4. approve the protected `npm` environment;
5. verify registry package, provenance, tarball contents, and a fresh clean install;
6. create the matching GitHub release.

`scripts/check-release.mjs` rejects a tag/version mismatch, missing provenance/public-access
metadata, wrong repository identity, or a package that is still private. The workflow cannot
publish from a fork. A rerun verifies the registry tarball against the local package integrity and
finishes without trying to overwrite an identical published version; any mismatch fails closed.

Do not weaken the workflow or commit an npm token when trusted publishing is unavailable. Keep the
candidate untagged until the publisher and protected environment are ready.
