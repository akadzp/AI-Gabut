# Agentic AI V4 — Batch 193

## Marker-Recovery Journal Lifecycle Attestation and Closure Freshness

Batch 193 adds a signed attestation lifecycle for the marker-recovery journal checkpoint introduced in Batch 192. The implementation is cumulative and keeps the journal checkpoint independent from the recovery-receipt checkpoint.

### Capabilities

- Issue Ed25519-attested snapshots binding the marker-recovery journal digest/count, status-transition and orphan-disposition checkpoint snapshots, current key lifecycle binding, and stable recovery-receipt checkpoint configuration.
- Audit attestation history, expiry, snapshot continuity, revocation, supersession, signing-key cutoff, and current recovery-receipt checkpoint health.
- Renew or revoke an attestation through short-lived, explicit confirmation challenges.
- Persist lifecycle events append-only in the recovery-receipt ledger and advance its external checkpoint through the existing one-event continuity/CAS recovery gate.
- Resume a persisted lifecycle event after a lost external-CAS response without duplicating the event.
- Include the marker-recovery journal checkpoint in the aggregate closure freshness snapshot.
- Optionally require a current marker-journal attestation before closure is considered complete.

### Strict-mode configuration

```bash
AGENTIC_REQUIRE_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_MARKER_RECOVERY_JOURNAL_ATTESTATION=true
```

Strict mode is meaningful only when the marker-recovery journal external checkpoint is configured and enrolled. The application refuses to issue a checkpoint attestation when the journal checkpoint is absent or not current.

The maximum attestation age is inherited from:

```bash
AGENTIC_CROSS_DOMAIN_RECOVERY_INTENT_CLOSURE_FRESHNESS_ATTESTATION_MAX_AGE_MS=300000
```

The default is five minutes; accepted values are 1,000–3,600,000 milliseconds.

### HTTP endpoints

- `POST /api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation`
- `GET /api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/audit?eventId=...`
- `POST /api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/prepare`
- `POST /api/agentic/recovery-audit/cross-domain/recovery-intent-closure/marker-recovery-journal/attestation/lifecycle/apply`

Lifecycle actions are `renew` and `revoke`. Renewal supersedes the prior attestation for current-decision use while retaining historical evidence. Revocation is append-only and immediately blocks current-decision use.

### Safety and recovery semantics

- A signing-key rotation can leave historical signatures verifiable while making the attestation stale for current decisions.
- Snapshot changes, journal mutations, expiry, revocation, or checkpoint loss prevent current-decision use.
- External checkpoint/local storage are not a single distributed transaction. Persisted events are resumed by operation ID and reconciled through CAS; they are not rewritten.
- Multi-event gaps, rollback, and unproven history are not repaired automatically.
- No private key material is included in this source archive.
