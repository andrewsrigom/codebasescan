# Edge cases and explicit behavior

“Implemented” means code exists. Refer to `VALIDATION.md` for which layers were actually executed.

| Case | Behavior / status |
| --- | --- |
| No AI model configured | Deterministic review; clearly labeled AI disabled. No fake generated analysis. |
| Local model unavailable, timeout, invalid JSON, invented evidence IDs | Candidate retained, assessment inconclusive; no cloud fallback. Real-model execution remains to validate. |
| AI calls something a false positive | Assessment only. Source severity and human disposition remain unchanged. |
| Human publishes while candidates are unresolved | Allowed with a rationale. Publication does not confirm them. |
| External scanner disabled | Visible skipped run, not clean. |
| Scanner binary missing or incompatible output | Visible failed run; do not claim coverage. |
| Target uses inline scanner suppressions | Trusted invocation disables Semgrep `nosem` and ignores Gitleaks allow-comments. Validate against pinned real binaries before release. |
| Scanner nonzero exit | Gitleaks exit 1 may mean findings; other unsupported exit states are errors. Contracts need real-binary validation. |
| Partial scanner parse / unmappable file location / output cap | Partial or failed result; do not silently treat as clean. |
| Same file flagged by multiple scanners | Preserve each source finding. No unsafe cross-tool deduplication. |
| Findings move between lines/scans | No automatic “resolved/new” claim; cross-scan baseline matching is not implemented. |
| Dependency manifest exists | Inventory declarations only; no CVE, resolved-version, or reachability claims. |
| Lockfile, IaC, Dockerfile, SQL file captured | Capture does not mean a specialized analysis was performed. Coverage remains scanner-specific. |
| `.env`, private key, binary, symlink, generated directory | Excluded and counted. This intentionally limits secret scanning coverage. |
| Target changes during read | Detect some size/race cases; skip/count where detected. Not an atomic snapshot guarantee. |
| Source changes before a resumed investigation | Fail rather than mix snapshot evidence. Start a new audit. |
| Model/scanner settings or trusted rules change mid-audit | Do not resume across a configuration or code upgrade. Finish/cancel and start a fresh audit; further enforcement is a hardening task. |
| Huge repository, deep paths, oversized source/output | Bounded snapshot, iteration, and process output. Report truncation. OS-enforced scanner resource isolation is still future work. |
| Navigate between audit IDs | Workspace is keyed by audit ID to avoid stale client state from another audit. |
| Browser closes or refreshes | Worker continues using the persisted queue; reopening reads store/events. |
| Worker absent | UI indicates offline and queued jobs remain queued. |
| Two workers start | Single local PID lock rejects the second. Stale PID reuse is conservative and may require operator intervention. |
| Worker dies during an audit | Dead-worker recovery requeues unfinished jobs, bounded attempts; checkpointer resume needs crash-injection release testing. |
| User cancels a running audit | Cancellation remains terminal; worker aborts cooperatively and cannot mark it completed later. |
| Same-origin duplicate publication | Compare-and-set allows one submission; second request is rejected. |
| Review during analysis | Not allowed. Review only paused/completed reports to avoid overwritten decisions. |
| Raw scanner staging survives power loss | Files remain private but unencrypted; manual cleanup after worker stop is currently required. |
| Directory permission error | Read errors/truncation or failure, never a safe result. |
| Repo root overlaps app storage | Registration rejected to prevent self-ingestion of checkpoints/reports. |
| Custom model URL / network project / public hosting | Not supported. No arbitrary backend endpoint or URL accepted from UI. |
| HTML in file/message/note | React and standalone HTML escape it. Markdown consumers must use a safe renderer. |
| Application DB from an untrusted source | Do not import it. Persisted-report schema validation and migration hardening are pending. |
| Windows filesystem/native dependencies | WSL2 first; native Windows is not validated. No cross-platform claim from Linux-only tests. |
| No findings | “No review candidates within this scope,” never “secure.” |
