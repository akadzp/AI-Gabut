# Batch 280 Validation Report

## Focused regression suites
Executed against the Batch 280 source tree:

- Batch 102 application entrypoint, dependency, import, and API checks: 13/13.
- Artifact tests: 3/3.
- Batch 104 durable execution lease: 7/7.
- Batch 276 external-attestation regressions: 3/3.
- Batch 277 lifecycle regressions: 3/3.
- Batch 278 external-attestation regressions: 3/3.
- Batch 279 lifecycle regressions: 3/3.
- Batch 280 external-attestation regressions: 3/3.

Total selected tests passed in the final combined run: **38/38**.

## Syntax and structure
- JavaScript/MJS/CJS syntax: **372/372 PASS** using `node --check` across the source tree.
- JSON syntax: **1/1 PASS**.
- Direct `node --check` passed for the modified core, application, server, and Batch 280 test files.
- Batch 102 import-resolution and application API reference checks passed.
- `package.json` declares Express as the HTTP runtime dependency.

## Archive checks
- ZIP integrity is tested with `zip -T` and `unzip -t`.
- The archive is extracted into a fresh directory; the final extracted source is checked again for syntax and focused regressions.
- Extracted file inventory and SHA-256 hashes are compared against the release source tree.
- Focused regression tests are rerun from the extracted tree.

## Limitations
- The full cumulative `npm test` suite was not run to completion; no full-suite PASS is claimed.
- A positive end-to-end flow that produces a current Batch 279 lifecycle receipt chain, attests every receipt with Batch 280, advances the independent checkpoint, and verifies the complete chain was not exercised.
- The HTTP listener was not started as an independent runtime smoke test. Route wiring, API exports, and syntax were checked.
