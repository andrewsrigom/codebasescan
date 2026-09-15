# Validation

Current release candidate: **0.4.0**. Last local v1 evidence refresh: **2026-09-14 BRT**.

This record covers the declared Node.js, JavaScript, TypeScript, React, and Next.js scope. It is not
a claim that every vulnerability is detectable, a recall estimate, or a security certification.

## Reference environment

- WSL2 with Ubuntu 24.04.4 LTS;
- Node.js 24.19.0 and npm 11.17.0;
- Next.js 16.3.4;
- Semgrep 1.176.1 and Gitleaks 8.30.1;
- dependency-cruiser 18.2.0 and jscpd 5.2.0.

Linux and WSL are the verified local environments. The GitHub Actions package matrix provides the
clean Node.js 22 evidence. Native Windows and macOS are not claimed.

## Deterministic release gate

| Check                    | Current evidence                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------- |
| Metadata                 | `codebasescan@0.4.0`; MIT, public package metadata, provenance enabled                    |
| Format, types, lint      | Passed with zero warnings                                                                 |
| Core tests               | 419 passed                                                                                |
| Fixture benchmark        | TP 56, FP 0, FN 0; precision 1.00, recall 1.00                                            |
| AST benchmark subset     | TP 11, FP 0, FN 0                                                                         |
| Next.js benchmark subset | TP 7, FP 0, FN 0                                                                          |
| React benchmark subset   | TP 9, FP 0, FN 0                                                                          |
| SaaS benchmark subset    | TP 9, FP 0, FN 0                                                                          |
| Integration tests        | 11 passed, including scanner isolation, cache, recovery, and no-network audit             |
| Production build         | Passed                                                                                    |
| Browser workflow         | 7 passed in Chromium                                                                      |
| Package audit            | 0 known vulnerabilities at `--audit-level=low`                                            |
| CLI diagnostics          | Runtime and bundled scanner checks passed; absent offline OSV data is an explicit warning |
| Baseline policy          | Same snapshot produced 0 new, 0 resolved, and 0 gated high findings                       |

The benchmark uses inert, declared ground truth. Its perfect fixture score is a regression signal,
not a real-world accuracy claim.

## Packed installation

Each smoke test packed the actual CLI, installed it into an empty generated project, and ran the
installed version, `doctor`, `init`, Codex skill installation, a static audit, report integrity, and
the loopback report server. The release scripts now fail mechanically above 2 MiB packed or 60 MiB
installed.

| Runtime / manager |   Tarball | Unpacked package | Installed dependencies | Install |  Audit |
| ----------------- | --------: | ---------------: | ---------------------: | ------: | -----: |
| Node 24 / npm     | 279,022 B |      1,255,358 B |           51,861,429 B | 10.87 s | 2.43 s |
| Node 24 / pnpm    | 279,022 B |      1,255,358 B |           51,945,629 B |  5.79 s | 2.53 s |
| Node 24 / Yarn    | 279,022 B |      1,255,358 B |           61,780,371 B |  8.79 s | 2.67 s |

All three installations remain below 60 MiB (62,914,560 bytes). The tarball contains 100 files.
Next.js, React, SQLite, LangChain, LangGraph, and model-provider packages are not installed with the
CLI.

## Real-project calibration

Sixteen authorized, structurally different repositories were scanned with workflow v84. The scans
captured source and manifests only: no target module, lifecycle script, dependency installation,
test, build, or application code ran.

| Project | Files | Findings | Candidate review | False-negative scope |
| ------- | ----: | -------: | ---------------- | -------------------- |
| P01     | 2,555 |       45 | 45 / 45          | sampled              |
| P02     | 1,200 |        9 | 9 / 9            | sampled              |
| P03     | 1,082 |       14 | 14 / 14          | sampled              |
| P04     | 1,411 |       14 | 14 / 14          | sampled              |
| P05     |   721 |        9 | 9 / 9            | sampled              |
| P06     |   123 |       19 | 19 / 19          | sampled              |
| P07     |   277 |       10 | 10 / 10          | sampled              |
| P08     |    40 |       11 | 11 / 11          | complete checklist   |
| P09     |   291 |        3 | 3 / 3            | sampled              |
| P10     |   329 |        4 | 4 / 4            | sampled              |
| P11     |   839 |        3 | 3 / 3            | sampled              |
| P12     |    90 |        5 | 5 / 5            | sampled              |
| P13     |    66 |        2 | 2 / 2            | sampled              |
| P14     | 2,255 |       57 | 57 / 57          | sampled              |
| P15     |    58 |        4 | 4 / 4            | complete checklist   |
| P16     |    35 |        1 | 1 / 1            | complete checklist   |

The corpus contains 11,372 supported files and 210 reviewed candidates: 160 true positives, 10
false positives, 40 not applicable, and 0 inconclusive. Observed sample precision is 94.1%; the
critical/high subset is 93.8% (15 true positives, 1 false positive, and 15 not applicable). Evidence,
location, and explanation assessments are correct or clear for all 210 reviewed candidates.

Every repository received a bounded false-negative review and three received a complete review of
the declared source-only checklist. The final ledgers contain no outstanding reproducible miss.
False-negative review is not complete for the whole corpus, so recall is intentionally omitted and
`accuracyClaimReady` remains false.

The cause-oriented action queue contains 427 tasks. A canonical root-cause, file, title, and expected
change comparison found 0 duplicate tasks and 0 candidates assigned to more than one task. Forty-five
repeated occurrences are intentionally collapsed into their shared root-cause task. The observed
actionable duplicate rate is therefore 0%, below the 5% v1 limit.

## Performance

A complete default audit of P03 processed 1,081 supported files and 5.56 MiB without truncation in
20.43 seconds wall time on the reference environment. Peak resident memory was 576,832 KiB. This is
below the 120-second v1 limit; it is a reference measurement, not a universal hardware guarantee.

## Safety and report contract

Automated tests cover snapshot containment, symlink and hostile-path rejection, bounded input,
timeouts, report escaping and hashes, secret redaction, explicit network and Git-history approval,
and the no-network default. Static output contains no executable script and includes validated HTML,
JSON, Markdown, SARIF, CycloneDX, policy, provenance, coverage, agent, and integrity artifacts.
Disabled, unsupported, partial, failed, and zero-finding states stay distinct.

## Release state

Version 0.3.0 remains the published npm release with verified provenance, matching tag, GitHub
release, and clean registry installation. Version 0.4.0 is the current candidate and is not published
by ordinary pushes. Its final tag, provenance, GitHub release, and registry verification require an
explicit release action after the candidate commit and CI are green.

## Reproduce

```bash
npm ci
npm run release:check
npm run test:e2e
npm run test:package:pnpm
npm run test:package:yarn
```

External scanner integration tests require trusted Semgrep and Gitleaks binaries on `PATH`. The
default audit has no model provider. External coding agents consume separately authorized,
versioned report and rule contracts.
