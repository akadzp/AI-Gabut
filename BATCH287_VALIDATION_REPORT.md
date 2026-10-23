# Batch 287 Validation Report

## Focused regression tests

Executed against the cumulative Batch 287 source tree:

- Batch 102 application entrypoint, authentication, dependency, import, and API checks: **13/13 PASS**.
- Artifact tests: **3/3 PASS**.
- Batch 270–287 external-attestation/lifecycle regression suites: **55/55 PASS** (three tests for each of Batch 270–286 and four tests for Batch 287).
- Batch 104 durable execution lease suite, run separately to reduce timing interference: **7/7 PASS**.

The combined Batch 102/artifact/Batch 270–287 run passed **71/71 tests**. The separately run Batch 104 suite passed **7/7 tests**. Total selected passing tests across the two runs: **78**.

Batch 287 tests cover empty-history safety, invalid action/reason/TTL rejection, fail-closed source-currentness preconditions, service/schema/checkpoint wiring, global recovery-gate convergence, and owner-scoped HTTP route registration.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **379/379 PASS**.
- `package.json` JSON parsing: **PASS**.
- Relative import resolution and application API references: **PASS** through Batch 102 regression tests.
- Express is declared in `package.json`; it is not installed in this validation environment, so HTTP listener startup was not tested.

## Full cumulative suite

The full cumulative `npm test` suite was **not run to completion for this batch**. This report makes no full-suite PASS claim. The focused regression runs and static syntax checks listed above completed successfully.

## Remaining integration coverage

- A positive end-to-end renewal flow from a verified-current Batch 286 external attestation through Batch 287 supersession, finalization receipt, and checkpoint advancement remains untested.
- A positive terminal-revocation flow through finalization receipt and descendant-generation rejection remains untested.
- HTTP listener startup remains untested in an environment with Express installed.

## Archive validation

The complete cumulative source tree was packaged, tested with `zip -T` and `unzip -t`, extracted to a fresh directory, and compared against the packaged file inventory using SHA-256.

- Packaged source/project files: **868**.
- ZIP entries, including directories: **887**.
- Missing files after extraction: **0**.
- Extra files after extraction: **0**.
- SHA-256 mismatches: **0**.
- Focused regression suite rerun against fresh extraction: **71/71 PASS**.
- Batch 104 durable execution lease suite rerun against fresh extraction: **7/7 PASS**.
- JavaScript-family syntax rerun against fresh extraction: **379/379 PASS**.

No GitHub commit was made.
