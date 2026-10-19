# Agentic AI V4 — Batch 187

## Recovery-intent status-transition attestation and explicit closure

Batch 187 introduces an append-only status-transition ledger for the recovery intents used by the recovery-attestation lifecycle. Each transition binds the intent ID, immutable recovery-intent digest, intent-event digest, prior and resulting statuses, prior and resulting record digests, signing-key lifecycle binding, sequence, and previous transition digest. When signing is configured as mandatory, every transition must carry a verified Ed25519 attestation. The latest transition for the latest intent must remain current; older transitions are checked for historical validity without incorrectly treating every old signing-key cutoff as a current-operation failure.

## Explicit orphan disposition

A missing or mismatched original challenge is not reconstructed. Operators can prepare an owner-scoped, ten-minute disposition challenge for a verified orphan and explicitly choose `quarantine` or `mark_unrecoverable`. Applying the challenge requires the same intent digest, orphan reason, transition-ledger snapshot, checkpoint snapshot, and signing-key lifecycle binding. The resulting disposition is append-only, CAS-written, Ed25519-attested, and idempotent on retry. A disposition closes the orphan's operational handling but never restores the missing evidence or makes the orphan usable for a current decision.

## Cross-domain closure enforcement

The closure audit joins status-transition history, orphan-disposition history, current recovery-intent records, lifecycle events, signing-key lifecycle, and the recovery-intent checkpoint. Unresolved orphans, pending intents, missing transition history, invalid signatures, stale key bindings, or non-current required checkpoints prevent closure or current-decision use. Explicitly dispositioned orphan evidence remains historical-only and continues to block decision use.

## Application API

- `auditRecoverySloCrossDomainRecoveryIntentStatusTransitions`
- `auditRecoverySloCrossDomainRecoveryIntentClosure`
- `prepareRecoverySloCrossDomainRecoveryIntentOrphanDisposition`
- `applyRecoverySloCrossDomainRecoveryIntentOrphanDisposition`

Authenticated HTTP routes expose transition audit, closure audit, disposition challenge preparation, and disposition application.

## Operational boundaries

- Disposition does not delete or rewrite the orphaned intent, challenge history, or lifecycle evidence.
- Disposition does not prove missing history retroactively.
- A disposition event is locally CAS-protected and signed; this batch does not add a separate external snapshot provider for the transition/disposition ledgers.
- A closed orphan is still not usable for a current decision.
- Signing-key rotation can make the latest transition or disposition stale; the audit fails closed.
- Private keys are not included in the source archive.

## Validation

Batch 187 focused tests cover signed transition history, explicit orphan disposition, idempotent replay, key-cutoff and confirmation guards, tamper detection, and HTTP route exposure. The complete cumulative source archive is syntax-checked, import-checked, tested in bounded groups, and revalidated after extraction. HTTP listener startup remains subject to the environment's missing `express` installation.

No GitHub commit was made.

Final validation note: all 174 cumulative test files completed in bounded groups with 1,280/1,280 passing. After the final transition-chain and challenge-snapshot binding hardening, the Batch 174–187 regression set was rerun and passed 113/113. A single monolithic test process exceeded the execution window; no assertion failures were observed in the completed bounded groups.
