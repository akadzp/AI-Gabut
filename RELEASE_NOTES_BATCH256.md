# Release Notes — Batch 256

Batch 256 adds signed external attestations for Batch 255 lifecycle finalization receipts.

### Added
- Batch 256 attestation event and binding digest.
- Cross-generation receipt-prefix and predecessor continuity validation.
- Signing-key cutoff/revalidation status.
- Snapshot, audit, and reconcile operations.
- Application wrappers and owner-scoped HTTP routes.
- Independent checkpoint snapshot coverage for Batch 256 events.

### Safety and recovery
- Empty source history cannot fabricate attestations.
- Incomplete or non-current Batch 255 source receipts block attestation issuance.
- Missing attestations require reconciliation; invalid signatures or bindings are unhealthy.
- Terminal revocation remains decision-blocking.

### Validation note
Focused tests and static/archive validation are reported separately from the full cumulative test suite. Full cumulative test completion is not inferred from focused PASS results.

### Validation results
- Focused regression coverage: 32/32 passed, including Batch 250–256 tests, Batch 102 entrypoint/dependency checks, and artifact tests.
- Syntax checks: 348/348 passed.
- Relative imports: 646 checked, none missing.
- Full cumulative `npm test` timed out at subtest 1129 without a final summary; it is not reported as passing.
- Direct HTTP listener startup was not verified because `express` is absent from the isolated runtime.
