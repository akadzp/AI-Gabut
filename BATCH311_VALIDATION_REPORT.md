# Batch 311 Validation Report

## Scope

Batch 311 implements renewal/revocation lifecycle operations for Batch 310 external attestations. The lifecycle binds intent/action events, the active attestation and its source finalization receipt, generation, signing-key lifecycle state, predecessor/replacement relationships, finalization receipts, and independent checkpoint state.

## Focused regression suites

The following suites were run separately against the working source:

| Suite | Result |
|---|---:|
| Batch 102 application/dependency/import/API checks | 13/13 PASS |
| Artifact persistence tests | 3/3 PASS |
| Batch 104 durable execution lease | 7/7 PASS |
| Batch 307 lifecycle | 5/5 PASS |
| Batch 308 external attestation | 4/4 PASS |
| Batch 309 lifecycle | 5/5 PASS |
| Batch 310 external attestation | 4/4 PASS |
| Batch 311 lifecycle | 5/5 PASS |
| **Selected regression total** | **46/46 PASS across separate suite runs** |

## Syntax and configuration

- JavaScript/MJS/CJS files checked: 403; all passed `node --check`.
- JSON files checked: 1; all parsed successfully.
- Batch 102 import/dependency checks passed.

## Archive checks

The final ZIP is tested with `zip -T` and `unzip -t`. It is extracted to a separate directory, then source-file inventory and SHA-256 hashes are compared. Post-extraction syntax and the selected regression suites are rerun before release.

## Not claimed

- Full cumulative `npm test` to a final TAP summary.
- Positive end-to-end provisioning of a verified-current Batch 310 attestation chain through Batch 311 renewal/revocation, finalization receipt creation, and checkpoint advancement.
- Crash injection at every lifecycle/checkpoint boundary.
- Live HTTP listener startup with runtime dependencies installed.

## Final ZIP inventory

- Source/project files: 1,012.
- ZIP entries: 1,031.
- Missing files after extraction: 0.
- Extra files after extraction: 0.
- SHA-256 mismatches between source and extracted files: 0.
- `zip -T`: PASS.
- `unzip -t`: PASS.
- Extracted JavaScript/MJS/CJS syntax: 403/403 PASS.
- Extracted selected regression suites: 46/46 PASS across separate suite runs.
