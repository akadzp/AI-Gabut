# Agentic AI V4 — Batch 277

Batch 277 introduces the lifecycle controller for Batch 276 external attestations.

The controller accepts only renewal and revocation. Preparation requires a current source-attestation audit, a healthy ledger, a usable checkpoint when enabled, and a current signing-key lifecycle binding. The challenge binds the target attestation, source finalization receipt, ledger head, ledger snapshot digest, generation, expiry, and confirmation phrase.

Application records signed lifecycle phases in the append-only ledger. Renewal creates a replacement and supersession link. Revocation is terminal. Finalization receipts bind the finalization event, action event, target, source receipt, key lifecycle, checkpoint, and predecessor receipt. Audit checks signatures, phases, generation continuity, receipt continuity, source bindings, and checkpoint usability. Reconciliation resumes pending challenges and advances checkpoints through the application wrapper.

The lifecycle is exposed through owner-authenticated application methods and five HTTP routes. Its audit is included in the overall recovery-gate convergence status and digest.
