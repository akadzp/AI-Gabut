# Architecture Migration Note

The repository was reorganized from the original monolithic `src/` layout into stable subsystem boundaries. Architecture V2 further separates generic core machinery, product apps, and external connectors while preserving the validated V1 behavior.

## V2 target

- `core/` — platform and AI-Gabut machinery.
- `apps/` — product AI identities such as Agentic and BukaOlshop CS.
- `connectors/` — external system adapters.
- `data/`, `runtime/`, `workspace/` — runtime/data boundaries retained at repository root.

This document records the migration history only; the current architecture is defined by `docs/technical/ARCHITECTURE-V2.md` and `README.md`.

## V1 production boundaries

- `core/platform` — bootstrap, configuration, lifecycle, shared infrastructure.
- `core/agent-engine` — Agentic AI identity: reasoning, planning, execution, memory, models, tools, evaluation, reliability.
- `connectors` — external service adapters.
- `core/storage` — storage service logic and providers.
- `core/sync` — synchronization/reconciliation between local state and external sources.
- `core/linux` — Linux/terminal/process/Git capabilities.
- `core/media` — media capabilities.
- `core/workspace` — project/workspace intelligence.
- `core/tasks` — jobs, scheduling and workflows.
- `core/security` — identity, permissions, policy, secrets, sandbox and audit.
- `core/api` — external API surface.
- `core/system` — migrations, maintenance and recovery.

## Data boundaries

- `data/` contains persistent application data.
- `runtime/` contains ephemeral execution state, sessions, caches and checkpoints.
- `workspace/` is the active user/project workspace.

## Historical validation

The former R2–R10 milestone checkers are retained under `tests/legacy-milestones/`. They document the incremental development process and can be used for regression/reference work, but they are deliberately not part of the production architecture or normal npm command surface.
