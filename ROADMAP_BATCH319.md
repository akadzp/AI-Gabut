# Batch 319 Roadmap

1. Validate the Batch 318 external-attestation source chain and current checkpoint before lifecycle mutation.
2. Support signed `renew` and terminal `revoke` operations with intent/action/supersession/finalization phases.
3. Recover missing phases and finalization receipts idempotently without fabricating source receipts.
4. Verify predecessor and replacement bindings, signature history, key-cutoff state, and generation monotonicity.
5. Reconcile independent checkpoints and feed Batch 319 into overall recovery-gate convergence.
6. Continue with Batch 320 external attestation of Batch 319 lifecycle finalization receipts.
