# Batch 319 — External Attestation Lifecycle

Batch 319 wraps Batch 318 external attestations with a signed renewal/revocation lifecycle. Operations require a current Batch 318 source audit and, when enabled, a current independent checkpoint. Lifecycle phases are append-only and bound to the target attestation, its source finalization receipt, generation, signing-key lifecycle, and predecessor/replacement events.

Renewal follows intent → renewed → superseded → finalized → finalization receipt. Revocation follows intent → revoked → finalized → finalization receipt and is terminal. Reconciliation resumes incomplete operations, repairs eligible missing finalization receipts from valid finalization events, advances independent checkpoints, and reruns the audit.

Owner-scoped routes are rooted at `/finalization-receipts/external-attestations/lifecycle/finalization-receipts/external-attestations/lifecycle` under the Batch 318 route root.
