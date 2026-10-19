# Agentic AI V4 — Batch 236

## External finalization-receipt attestation lifecycle

Batch 236 adds a signed lifecycle over Batch 235 external attestations. It supports explicit `renew` and terminal `revoke` operations through challenge-bound intent, action, supersession, and finalization events.

### Guarantees

- Every lifecycle phase is signed and appended to the existing continuity ledger.
- Challenges bind the target attestation, source finalization receipt, ledger snapshot, generation, reason digest, and prepared signing-key binding.
- Renewals produce a predecessor/replacement chain; revocation is terminal and descendant lifecycle events are unhealthy.
- Event operation IDs are deterministic and retries reuse an identical event or reject conflicting bindings.
- Audits verify signatures, generation order, source receipt bindings, phase cardinality, key-cutoff state, and checkpoint freshness.
- Reconciliation resumes pending challenges from their stored confirmation phrase, advances the configured independent checkpoints between phases, and re-audits before reporting completion.
- Empty history is read-only; lifecycle mutation requires a current Batch 235 source audit.
- The overall recovery-gate convergence includes Batch 236 whenever lifecycle events exist.

### API routes

Base path extends the Batch 235 external-attestation root with `/lifecycle`:

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `POST /reconcile`

Routes use the existing authenticated owner identity. No new external provider or credentials are bundled.

### Validation scope

Batch-specific tests cover empty-history fail-closed behavior and API/route wiring. Syntax/import/archive validation is distinct from a complete live-provider end-to-end renewal/revocation run; such a run must not be inferred from focused tests.
