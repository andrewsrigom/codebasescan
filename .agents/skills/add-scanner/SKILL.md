---
name: add-scanner
description: Add or update a trusted local scanner adapter without weakening source and evidence boundaries.
---

Read AGENTS.md and docs/THREAT_MODEL.md. Before adding a scanner, identify its exact CLI version, license, output schema, offline/network behavior, exit code contract, and supported files. Use official documentation.

Invoke only a trusted allowlisted binary with fixed validated argument arrays and shell disabled. Use the private bounded staging snapshot, never target configuration or scripts. Add output/timeout/cancellation limits. Strip raw secrets and unrelated file paths before normalization or persistence.

Return explicit completed/partial/skipped/failed coverage. Preserve source severity and finding identity. Add golden output fixtures for successful findings, zero findings, error output, invalid JSON, truncated output, unsupported files, and unmappable locations. Never convert an exception into a clean scan.

Run core and real-binary integration tests. Document any untested contract. Do not bundle third-party binaries or incompatible rule packs without a separate distribution review.
