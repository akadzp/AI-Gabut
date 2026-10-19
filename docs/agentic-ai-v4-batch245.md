# Agentic AI V4 — Batch 245

## Purpose

Batch 245 adds a signed renewal/revocation lifecycle for Batch 244 external attestations. Each lifecycle action binds the active Batch 244 attestation, its Batch 243 lifecycle finalization receipt, the challenge and reason, signing-key lifecycle binding, and an independent checkpoint state.

## Lifecycle and integrity

- Supported actions are `renew` and `revoke`; unsupported actions fail closed.
- Renewal follows intent → renewed → superseded → finalized → finalization receipt.
- Revocation follows intent → revoked → finalized → finalization receipt and remains terminal.
- Every phase is signed and appended to the continuity ledger with deterministic operation IDs.
- Audit verifies historical signatures, phase ordering, challenge uniqueness, monotonically increasing generations, target/predecessor bindings, supersession, terminal revocation, receipt binding, and predecessor receipt continuity.
- A missing finalization receipt or non-current independent checkpoint yields `recovery_required`; invalid signatures or bindings yield `unhealthy`; a terminal revocation yields `decision_blocked`.
- Signing-key cutoff is captured at challenge preparation and checked before intent persistence. Resume/reconcile can complete already-started operations without changing their deterministic operation IDs.
- Batch 245 events are included in the independent checkpoint snapshot and overall recovery-gate convergence.

## API

Owner-scoped authenticated routes are added under `/finalization-receipts/external-attestations/lifecycle`:

- `POST /prepare`
- `POST /apply`
- `GET /audit`
- `GET /snapshot`
- `POST /reconcile`

## Validation scope

Focused regression tests cover empty-history fail-closed behavior, source-current preconditions, application API wiring, checkpoint snapshot inclusion, and route registration. Syntax/import/archive validation is performed against the extracted final ZIP. The full cumulative test suite and a full positive end-to-end renewal/revocation run are not claimed as passing unless they produce a final successful summary.

## GitHub

No commit performed.
