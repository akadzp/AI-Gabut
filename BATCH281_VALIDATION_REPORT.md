# Batch 281 Validation Report

## Focused regression suites
The following suites were executed on the Batch 281 source tree, with final extracted-tree checks also performed:

- Batch 102 application entrypoint, dependency, import, and API checks: **13/13 PASS**.
- Artifact tests: **3/3 PASS**.
- Batch 104 durable execution lease: **7/7 PASS when run in isolation**.
- Batch 279 lifecycle regressions: **3/3 PASS**.
- Batch 280 external-attestation regressions: **3/3 PASS**.
- Batch 281 lifecycle regressions: **3/3 PASS**.

A completed focused run passed **32/32 tests** before final packaging. On a later combined run against the extracted release tree, Batch 104's lease-heartbeat test transiently failed with `WORK_EXECUTION_LEASE_LOST`; the same Batch 104 suite then passed **7/7** when rerun in isolation. Treat this as a timing-sensitive existing regression under combined load, not as a full-suite pass.

The Batch 281 suite checks empty-history read-only behavior, refusal to mutate without a current Batch 280 external attestation, API and HTTP wiring, independent checkpoint snapshot coverage, and lifecycle ledger schema bindings.

## Syntax and structure
- JavaScript/MJS/CJS syntax: **373/373 PASS** using `node --check` across the source tree and again after extraction.
- JSON syntax: **1/1 PASS**.
- Batch 102 relative-import resolution and application API reference checks passed.
- `package.json` declares Express as the HTTP runtime dependency.

## Archive checks
- ZIP integrity checked with `zip -T` and `unzip -t`.
- The archive was extracted into a fresh directory; source inventories and SHA-256 hashes were compared.
- Extracted source count matched the release tree exactly; no missing, extra, or hash-mismatched files.
- Batch 281 and Batch 280 regression tests were rerun from the extracted tree and passed.

## Limitations
- The full cumulative `npm test` run did not complete within the execution window. It reached subtest 844 with no `not ok` visible in the captured output, but no final TAP summary was produced; therefore, no full-suite PASS is claimed.
- A positive end-to-end renewal/revocation flow requiring a current Batch 280 external-attestation chain was not exercised.
- The HTTP listener was not independently started; route wiring, application API references, and syntax were checked.
- No GitHub commit was made.
