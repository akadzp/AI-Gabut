# Batch 285 Validation Report

## Focused regression suites

Executed against the cumulative Batch 285 source tree:

- Batch 102 application entrypoint, authentication, dependency, import, and API checks: **13/13 PASS**.
- Artifact tests: **3/3 PASS**.
- Batch 283 lifecycle regressions: **3/3 PASS**.
- Batch 284 external-attestation regressions: **3/3 PASS**.
- Batch 285 lifecycle regressions: **3/3 PASS**.
- Batch 104 durable execution lease tests, run separately to reduce timing interference: **7/7 PASS**.

The combined focused run passed **25/25 tests**; the separate Batch 104 run passed **7/7 tests**. Total selected passing tests: **32**.

Batch 285 tests cover empty-history safety, rejection of mutation when Batch 284 source attestations are not current, owner-scoped API and route wiring, checkpoint inventory, source target selection, and malformed lifecycle event schema rejection.

## Syntax and configuration

- JavaScript/MJS/CJS files checked with `node --check`: **377/377 PASS**.
- `package.json` JSON parsing: **PASS**.
- Relative-import resolution and application API references: **PASS** through Batch 102 regression tests.
- Express is declared in `package.json`, but the runtime package is not installed in this environment; HTTP listener startup was not tested.

## Full cumulative suite

`npm test` was attempted. It timed out at the execution limit after output had reached subtest 1,129. No failing test was visible in the captured output before timeout, but no final TAP summary was produced. Therefore, **the full cumulative suite is not claimed as passing**.

## Archive validation

The final cumulative source tree was packaged into a ZIP, checked with `zip -T` and `unzip -t`, extracted into a fresh directory, and compared with the packaged source inventory using SHA-256. The final counts and results are recorded in the handoff summary. No GitHub commit was made.

## Remaining integration coverage

- A positive end-to-end flow from a fully current Batch 284 attestation through Batch 285 renewal/revocation, finalization receipt creation, and checkpoint advancement remains untested.
- HTTP listener startup remains untested because Express is absent from the validation environment.

## Final ZIP integrity

- Packaged source/project files: **856**.
- ZIP entries: **875**.
- `zip -T`: **PASS**.
- `unzip -t`: **PASS**.
- Fresh extraction comparison: **0 missing files, 0 extra files, 0 SHA-256 mismatches**.
- Re-run against the fresh extracted tree: Batch 285 regression tests **3/3 PASS** and JavaScript-family syntax **377/377 PASS**.
