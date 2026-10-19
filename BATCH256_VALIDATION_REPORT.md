# Batch 256 Validation Report

## Scope

Batch 256 adds signed external attestations for Batch 255 lifecycle finalization receipts, including receipt-prefix continuity, predecessor-attestation continuity, signing-key cutoff/revalidation, independent checkpoint snapshot inclusion, and owner-scoped API routes.

## Regression tests

- Batch 250–256 focused regression files: **16/16 passed**.
- Batch 102 entrypoint/dependency checks plus artifact tests: **16/16 passed**.
- Combined focused coverage: **32/32 passed**.
- The same focused tests are rerun against the source extracted from the final ZIP.

Coverage includes empty-history safety, source gating, event-type consistency, source receipt binding, checkpoint snapshot registration, application API registration, and HTTP route registration.

## Static checks

- JavaScript/MJS/CJS syntax: **348 checked, 0 failed**.
- Relative import references: **646 checked, 0 missing**.
- JSON files: **1 parsed, 0 invalid**.
- Application API and route references: passed in focused regression tests.

## Full-suite limitation

`npm test` did not finish within the 120-second execution window. Captured output reached subtest **1129** (Batch 169) and did not produce a final TAP summary. No `not ok` entries were present in the captured partial output. This is not a full-suite pass.

## HTTP runtime limitation

Direct HTTP listener startup was not verified because `express` is not installed in the isolated runtime. The project declares its dependency, and route/application wiring is covered by regression tests.

## Archive verification

The final ZIP is checked with `zip -T` and `unzip -t`, extracted into a clean directory, and compared against the packaged source using SHA-256 manifests. Syntax checks, import checks, and focused regression tests are repeated against the extracted source.

## Final archive metrics

- Source/project files: **701**.
- ZIP entries: **720**.
- ZIP integrity (`zip -T` and `unzip -t`): passed.
- Extraction comparison: **701 files compared, 0 missing, 0 extra, 0 SHA-256 differences**.
- Post-extraction syntax: **348/348 passed**.
- Post-extraction import resolution: **646 checked, 0 missing**.
- Post-extraction focused regression tests: **32/32 passed**.
