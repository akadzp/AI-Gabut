# Batch 309 Validation Report

## Focused tests

The following focused tests were executed successfully: `agentic-entrypoint-dependencies-batch102.mjs`, `agentic-artifacts.mjs`, `agentic-durable-execution-lease-batch104.mjs`, `agentic-recovery-slo-v4-batch306-external-attestation.mjs`, `agentic-recovery-slo-v4-batch307-external-attestation-lifecycle.mjs`, `agentic-recovery-slo-v4-batch308-external-attestation.mjs`, and `agentic-recovery-slo-v4-batch309-external-attestation-lifecycle.mjs`.

Result: 41 tests passed; 0 failed. The same focused test set passed after extracting the release ZIP.

## Batch 309 coverage

1. Empty history is read-only and does not fabricate lifecycle events or receipts.
2. Invalid actions, reasons, and TTLs are rejected before mutation.
3. Lifecycle mutation requires a verified-current Batch 308 external attestation.
4. Service methods, checkpoint inventory, overall convergence, and owner-scoped HTTP routes are wired.
5. Ledger schema validation covers lifecycle generation and receipt bindings.

## Static and archive checks

- JavaScript/MJS/CJS syntax: 401/401 passed before packaging and 401/401 passed after extraction.
- JSON parse: 1/1 passed before packaging and 1/1 passed after extraction.
- Relative import resolution and HTTP API reference checks passed through Batch 102 tests.
- ZIP integrity: `zip -T` passed; `unzip -t` reported no errors.
- Complete source files: 1,000.
- ZIP entries: 1,019 (1,000 files and 19 directory entries).
- Extracted file comparison: 1,000/1,000 files matched by SHA-256; 0 missing, 0 extra, 0 differences.

## Explicit limitations

The complete cumulative `npm test` suite was not run to a final TAP summary. Positive end-to-end renewal/revocation against a fully provisioned verified-current source chain, crash-injection recovery at every phase boundary, and HTTP listener startup with runtime dependencies installed are not claimed as passed.
