# Batch 03 Correction — Agentic Session/Execution

This delta corrects the Batch 03 session persistence contract and normalizes test filenames.

## Changes

- Fix `putChatSession()` so new records default to `overwrite:false`, while updates carrying `expectedVersion` use `overwrite:true`.
- Keep optimistic version checking intact.
- Update Agentic execution tests to create an explicit chat session before calling `chat()`.
- Rename Agentic test files so roadmap/version labels are not embedded in source filenames:
  - `agentic-v3.mjs` → `agentic.mjs`
  - `agentic-execution-v3.mjs` → `agentic-execution.mjs`
  - `agentic-sessions-v3.mjs` → `agentic-sessions.mjs`
- Update `package.json` test references.

V1/V2/V3 remain documentation/roadmap phase labels only. They are not code-version namespaces.

## Apply

Extract/merge this ZIP over the repository.

Delete the three old `*-v3.mjs` test files listed in `DELETE.txt`.

Then run:

```bash
npm run test:agentic
npm test
npm run check:architecture
```

Do not modify source manually before testing.
