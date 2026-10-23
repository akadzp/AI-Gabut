# Batch 315 Validation Report

## Final source validation
- JavaScript/MJS/CJS syntax checks: 407 files, 0 syntax errors.
- `package.json` JSON parsing: PASS.
- Relative import and HTTP application API reference checks (Batch 102 regression suite): PASS.
- Focused regression suites across Batch 102, artifact persistence, Batch 104, and Batches 309–315: 57/57 tests passed when run in separate test invocations.
- Batch 315-specific suite: 6/6 PASS.
- `zip -T` and `unzip -t` are required and run against the final archive; extracted-tree hashes are compared before delivery.

## Test-run notes
A single combined invocation of the selected suites exceeded the execution timeout and showed one transient Batch 104 cross-process exclusion failure. Batch 104 was rerun independently and passed 7/7. Remaining selected suites were completed in separate invocations with complete TAP summaries. This is not a claim that the full cumulative `npm test` suite passed.

## Not claimed
- Full cumulative `npm test` completion.
- Positive end-to-end provisioning through a current Batch 314 external attestation, Batch 315 renewal/revocation, receipt finalization, and checkpoint advancement.
- Crash-injection at every lifecycle phase boundary.
- Live HTTP listener startup with runtime dependencies and end-to-end requests.

The final ZIP SHA-256 is provided in the delivery message rather than embedded here, avoiding a self-referential archive hash.
