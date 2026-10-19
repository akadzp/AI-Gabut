# Agentic AI V4 — Batch 230

## External-attestation finalization-receipt renewal/revocation lifecycle

Batch 230 adds an owner-scoped, signed append-only lifecycle for Batch 229 external attestations of Batch 228 finalization receipts. The lifecycle supports challenge-bound `renew` and terminal `revoke`, with intent, action, supersession (renewal only), and finalization events. Each event is signed through the existing continuity ledger and bound to a deterministic operation ID.

### Renewal and cross-generation supersession

A renewal binds the target attestation ID/digest and generation, the lifecycle challenge and intent, the renewal action, the replacement attestation, and the predecessor ID/digest. The replacement remains in the Batch 229 attestation chain and increments its generation. Its binding digest covers the current checkpoint fingerprint and lifecycle references. The supersession event and finalization event bind the same predecessor/replacement pair. Audit verifies the signed chain and rejects missing or conflicting links.

### Terminal revocation

Revocation is finalized as a signed lifecycle event and is terminal. A later attestation request or lifecycle preparation is rejected. The B229 attestation audit and higher-level recovery-gate audit return `decision_blocked` for terminal revocation, even if an external checkpoint is stale; this is deliberately fail-closed.

### Signing-key cutoff

A stale attestation caused solely by a verified signing-key cutoff can be renewed or revoked when signature history and receipt bindings remain valid. A replacement is signed with the current key and records key-cutoff revalidation. A key change after a renewal challenge is prepared prevents intent creation; if the intent was already persisted, recovery continues under the current key and records whether the replacement revalidated the cutoff.

### Independent checkpoint recovery

The existing independent Batch 229 checkpoint snapshot now includes Batch 230 lifecycle events in addition to Batch 228 finalization receipts and Batch 229 external attestations. Lifecycle mutations advance configured checkpoints through the existing multi-checkpoint advancement workflow. A pending external checkpoint yields `recovery_required`; the lifecycle reconcile endpoint invokes checkpoint reconciliation and returns the resulting audit. No new provider or credential is assumed.

### HTTP surface

Authenticated owner-scoped routes are registered beneath the existing finalization-receipt external-attestation route:

- `POST .../lifecycle/prepare`
- `POST .../lifecycle/apply`
- `GET .../lifecycle/audit`
- `GET .../lifecycle/snapshot`
- `POST .../lifecycle/reconcile`

### Validation limits

- Batch 230 focused tests: 2/2 PASS.
- Focused Batch 226–230 regression group: 11/11 PASS.
- Batch 225 regression tests were rerun after Batch 230 changes: 2/2 PASS.
- A combined Batch 220–230 command exceeded the execution budget before producing results; it is not reported as passing.
- Positive end-to-end renewal/revocation through a fully initialized Batch 229 receipt chain is not claimed as passing. Live HTTP startup and full cumulative `npm test` are also not claimed as passing.
