# Agentic AI V4 — Batch 311

Batch 311 adds a renewal/revocation lifecycle for Batch 310 external attestations.

## Lifecycle and binding
The lifecycle uses intent, renewed/revoked, superseded, finalized, and finalization-receipt events. Bindings include the active Batch 310 attestation ID/digest/generation, its source finalization receipt ID/digest, challenge and action, reason digest, signing-key lifecycle binding, key-cutoff state, intent/action event references, replacement attestation, and predecessor links.

## Audit and recovery
The audit validates signed event history, generation continuity, phase ordering, receipt/finalization linkage, source receipt existence, predecessor/replacement continuity, signing-key cutoff state, and independent checkpoint usability. A terminal revocation remains decision-blocking. Reconciliation advances checkpoints around recovered phases and resumes pending challenges without rewriting existing source receipts.

## API
The owner-scoped root is nested below the Batch 310 external-attestation root and exposes `POST /prepare`, `POST /apply`, `GET /audit`, `GET /snapshot`, and `POST /reconcile`.

## Validation
The focused Batch 311 suite passes 5/5. Selected regression suites for Batch 102, artifact tests, Batch 104, and Batches 307–311 passed when run separately. Syntax checks and archive validation are recorded in `BATCH311_VALIDATION_REPORT.md`. Full cumulative tests and positive end-to-end chain provisioning are not claimed as complete. No GitHub commit was made.
