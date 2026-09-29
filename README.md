# AI-Gabut V4 GitHub Actions worker

This directory contains the proposed GitHub Actions worker for the V4 autonomous batch loop.

The workflow:
- runs hourly or manually;
- serializes runs with Actions concurrency;
- works on `agentic/v4-autonomous`, leaving `main` untouched;
- invokes the official `openai/codex-action` with a workspace permission profile;
- requires `OPENAI_API_KEY` as a GitHub Actions secret;
- asks Codex to implement exactly one V4 batch and validate it;
- runs `npm test` after the agent step;
- publishes a delta artifact;
- commits the resulting batch to the autonomous branch.

Before enabling this for unattended production use, review the branch protection and secret policy. The current design intentionally keeps `main` untouched; promotion to `main` remains a separate governance step.
