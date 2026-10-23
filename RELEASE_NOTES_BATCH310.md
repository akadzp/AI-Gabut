# Release Notes — Batch 310

## Added
- External attestations for Batch 309 lifecycle finalization receipts.
- Receipt binding to finalization event, challenge/action, target/source receipt, intent/action events, replacement attestation, receipt-chain prefix, checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle state.
- Cross-generation predecessor ID/digest continuity and signature-history validation.
- Key-cutoff detection and revalidation checks.
- Independent checkpoint-aware reconciliation and overall recovery-gate convergence.
- Owner-scoped HTTP endpoints for attest, audit, snapshot, and reconcile.
- Focused Batch 310 regression tests.

## Safety behavior
- Missing attestations require recovery.
- Invalid signatures, bindings, or predecessor chains produce an unhealthy audit.
- A verified terminal source revocation remains decision-blocking.
- Existing source receipts are not rewritten by attestation recovery.

## Validation note
Focused regression suites passed when run separately. One Batch 104 concurrency test had a transient failure on its first run and passed on standalone rerun. The combined test invocation timed out, and the full cumulative `npm test` suite is not claimed as passing.

## GitHub
No commit made.
