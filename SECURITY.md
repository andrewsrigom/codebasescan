# Security policy

Traceward is an early local-only defensive review tool. It is not a penetration-testing service, compliance assessment, or guarantee of software security. Do not use its output as the sole release gate for sensitive systems.

## Supported deployment

One trusted OS user, one local worker, a loopback-only UI, and authorized repositories. WSL2/Linux is the initial development target. No public, LAN, multi-user, tunneled, or hosted deployment is supported. There is no authentication or tenant isolation.

Read `docs/THREAT_MODEL.md` before reviewing nontrivial repositories. The source boundary is not a hardened sandbox. Model/scanner dependencies and local daemons are trusted. Data is not encrypted at rest by the app.

## Reporting a vulnerability

Do not include real source code, credentials, tokens, local paths, or unredacted reports in public issues. Share a minimal inert reproduction.

Before the first public release, the owner must enable GitHub private vulnerability reporting and put the verified reporting route here. No contact email, published repository URL, or security-response SLA is invented in this starter. Until that route exists, this is not a supported public release.

## Disclosure discipline

A valid report should identify the affected version, trust assumption violated, minimal reproduction, impact, and suggested mitigation. Do not test against other people's repositories/services without authorization. Do not publish exploitation details before the owner has had an opportunity to address a reported issue.
