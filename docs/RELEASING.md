# Releasing

CodebaseScan is intentionally protected by `"private": true`. Ordinary branch pushes never
publish the package.

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
Immediately before publishing, confirm that the `codebasescan` npm name is available or controlled
by the maintainer.

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

1. update the changelog date;
2. change `"private": true` to `"private": false`;
3. run `npm run release:check` again and commit that one release change;
4. create and push the exact tag `v<package-version>`;
5. approve the protected `npm` environment;
6. verify the registry package, provenance, tarball contents, and a fresh `npm install --save-dev`;
7. create the matching GitHub release.

`scripts/check-release.mjs` rejects a tag/version mismatch, missing provenance/public-access
metadata, wrong repository identity, or a package that is still private. The workflow cannot
publish from a fork.

If npm trusted publishing cannot be configured before the first package exists, do not weaken the
workflow or commit a token. The maintainer must authenticate directly with npm and approve the
initial publication with 2FA. Configure `publish.yml` as the trusted publisher immediately after
the package exists; later versions then use short-lived OIDC credentials only.
