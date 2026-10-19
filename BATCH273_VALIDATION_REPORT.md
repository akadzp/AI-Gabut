# Batch 273 — Validation Report

## Scope

Batch 273 adds a signed renewal/revocation lifecycle for Batch 272 external attestations, including monotonic lifecycle generations, cross-generation supersession, lifecycle finalization receipts, signing-key cutoff handling, checkpoint-aware recovery, owner-scoped API wrappers, HTTP routes, and global recovery-gate convergence.

## Regression tests

Executed against the Batch 273 working source tree:

- Batch 102 application entrypoint, authentication, dependency, import, and API checks: 13/13 PASS.
- Artifact tests: 3/3 PASS.
- Batch 269–273 focused regressions: 15/15 PASS.
- Total selected regression tests: **31/31 PASS**.
- Batch 273-specific tests: **3/3 PASS**.

Batch 273 tests cover empty-history read-only behavior, rejection when the source Batch 272 attestation is not current, invalid action rejection, owner-scoped API wiring, independent checkpoint snapshot coverage, Batch 272 source-receipt binding, lifecycle event schema checks, and global recovery-gate integration.

## Syntax, import, and configuration

| Check | Result |
|---|---:|
| JavaScript/MJS/CJS syntax | 365/365 PASS |
| Syntax after ZIP extraction | 365/365 PASS |
| JSON parsing | 1/1 PASS |
| Relative import resolution | PASS (Batch 102 regression) |
| Application API references | PASS (Batch 102 regression) |
| Express dependency declaration | PASS (Batch 102 regression) |

## Archive validation

| Check | Result |
|---|---:|
| Source/project files | 792 |
| ZIP entries | 811 |
| `zip -T` | PASS |
| `unzip -t` | PASS |
| Missing files after extraction | 0 |
| Extra files after extraction | 0 |
| SHA-256 source mismatches | 0 |
| Regression tests after extraction | 31/31 PASS |

## Validation limits

The full cumulative `npm test` suite was not run to completion; no full-suite PASS is claimed. A positive end-to-end renewal/revocation flow starting from a fully current Batch 272 external attestation was not exercised in this batch.

Direct HTTP listener startup could not be completed in the validation environment because `express` was not installed in the extracted working tree. `package.json` declares `express` (`^4.21.2`), and the Batch 102 dependency/API regression passed, but installing dependencies timed out in this environment. The optional `verify:recovery-slo-export` command requires a `--bundle <file.json>` input, which was not supplied, so that command is not a Batch 273 regression result.

No GitHub commit was made.
