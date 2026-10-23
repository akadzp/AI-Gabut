# Agentic AI V4 — Batch 278 Roadmap

## Scope
External attestation for Batch 277 lifecycle finalization receipts, cross-generation receipt continuity, signing-key lifecycle verification, and independent checkpoint recovery.

## Invariants
- Attestation mutation requires a healthy, current Batch 277 lifecycle receipt audit and a usable independent checkpoint.
- Every attestation binds a finalization receipt and its finalization event, challenge/action, target and replacement references, receipt-chain prefix digest, checkpoint fingerprint, lifecycle audit digest, and signing-key lifecycle binding.
- Attestation generations form a predecessor-linked append-only chain.
- Missing attestations or stale checkpoints require recovery; invalid signatures or bindings fail closed.
- Terminal source revocation remains decision-blocking and cannot be undone by attestation.
- The global recovery gate includes Batch 278 status and generation binding digest.

## API
Mounted below `${batch277ExternalAttestationLifecycleRoot}/finalization-receipts/external-attestations`:
- `POST /attest`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Next logical stage
Batch 279: renewal/revocation lifecycle for Batch 278 external attestations, including supersession and lifecycle finalization receipts.
