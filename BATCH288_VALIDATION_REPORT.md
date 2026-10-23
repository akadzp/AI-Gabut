# Batch 288 Validation Report

## Focused regression tests

Executed against the cumulative Batch 288 source tree:

- Batch 102 application entrypoint, authentication, dependency, import, and API checks: **13/13 PASS**.
- Artifact tests: **3/3 PASS**.
- Batch 104 durable execution lease suite, in the same focused run: **7/7 PASS**.
- Batch 286 external-attestation regression suite: **3/3 PASS**.
- Batch 287 external-attestation lifecycle regression suite: **4/4 PASS**.
- Batch 288 external-attestation regression suite: **3/3 PASS**.

Combined focused regression result: **33/33 PASS**.

Batch 288 tests cover empty-history safety, no fabricated receipts/attestations, owner-scoped service/API wiring, independent checkpoint inventory, overall recovery-gate convergence, HTTP route registration, and ledger schema binding requirements.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **380/380 PASS**.
- `package.json` JSON parsing: **PASS**.
- Relative import resolution and application API references: **PASS** through Batch 102 regression tests.
- Express is declared in `package.json`; it is not installed in this validation environment, so HTTP listener startup was not tested.

## Full cumulative suite

The full cumulative `npm test` suite was **not run to completion for this batch**. This report makes no full-suite PASS claim. Focused regression runs and static syntax checks completed successfully.

## Remaining integration coverage

- A positive end-to-end flow from a verified-current Batch 287 lifecycle receipt chain through Batch 288 attestation and checkpoint advancement remains untested.
- HTTP listener startup remains untested in an environment with Express installed.

## Archive validation

The complete cumulative source tree was packaged, checked with `zip -T` and `unzip -t`, extracted to a fresh directory, and compared against the packaged file inventory using SHA-256. Focused regression tests and JavaScript-family syntax checks were repeated against the extracted tree before release.

No GitHub commit was made.

Final archive measurements:

- Source/project files: **874**.
- ZIP entries including directories: **893**.
- ZIP integrity (`zip -T`): **PASS**.
- ZIP integrity (`unzip -t`): **PASS**.
- Fresh extraction inventory: **874/874 files matched**.
- Missing files: **0**; extra files: **0**; SHA-256 mismatches: **0**.
- Fresh-extraction focused regression result: **33/33 PASS**.
- Fresh-extraction JavaScript-family syntax: **380/380 PASS**.
