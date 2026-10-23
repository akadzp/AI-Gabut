# Agentic AI V4 — Batch 288

Batch 288 externalizes proof of Batch 287 lifecycle finalization receipts through a signed attestation chain.

## Binding model

Each attestation binds the receipt ID/digest/generation, lifecycle finalization event ID/digest, challenge/action, target and source receipt identities, intent/action event digests, replacement identity where applicable, source receipt-prefix digest, checkpoint fingerprint, source lifecycle audit digest, source/current signing-key lifecycle bindings, key-cutoff state, and predecessor attestation identity/digest.

## Recovery model

The application reconciles Batch 287 source lifecycle state before attesting receipts, advances independent checkpoints before and after attestation when required, then audits the resulting chain. Empty history remains read-only and does not fabricate receipts or attestations. Invalid signatures or bindings are unhealthy; missing attestations or stale checkpoints require recovery; a verified terminal revocation remains decision-blocked.

## Interfaces

Owner-scoped endpoints are registered under the Batch 288 finalization-receipt external-attestation root:

- `POST /attest`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

The full path is derived from the Batch 287 external-attestation lifecycle root.
