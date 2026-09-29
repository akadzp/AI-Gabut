# AI-Gabut V4 GitHub Actions worker

This ZIP has the correct repository layout.

Extract it at the root of the AI-Gabut repository so the workflow becomes:

.github/workflows/v4-batch.yml

The workflow supports:
- hourly schedule;
- manual `workflow_dispatch`;
- serialized V4 batch runs;
- autonomous branch `agentic/v4-autonomous`;
- OpenAI `codex-action@v1`;
- `OPENAI_API_KEY` GitHub Actions secret;
- exactly one V4 batch per run;
- focused validation plus `npm test`;
- a downloadable delta artifact;
- commit/push of the completed batch to `agentic/v4-autonomous`.

Important:
1. This first version is intentionally hourly/manual, not yet self-chaining.
2. Do not put the workflow file at repository root.
3. After pushing the workflow to `main`, open GitHub → Actions → AI-Gabut V4 Batch Worker → Run workflow.
4. The workflow expects the `OPENAI_API_KEY` repository Actions secret.
5. The current workflow leaves `main` untouched and publishes implementation to `agentic/v4-autonomous`.
