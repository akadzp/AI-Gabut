# AI-Gabut Architecture V2 — Boundary Contract

AI-Gabut is a modular personal-AI platform. `core/agent-engine` contains generic agent intelligence; product identities live under `apps/`.

## Top-level boundaries

- `core/platform` — bootstrap, configuration, lifecycle, events, registries, diagnostics and system composition.
- `core/agent-engine` — reasoning, planning, goals, context/memory, model routing, agent tool selection, evaluation and agent reliability.
- `connectors` — adapters to external systems and provider APIs. A connector does not become the Agent's memory or reasoning layer.
- `core/storage` — storage abstractions and implementations. Persistent data lives outside `backend/`.
- `core/sync` — synchronization/reconciliation between local workspace state and external systems. It must support changes made by both humans and agents.
- `core/linux` — operating-system capabilities: filesystem/process/package/service/system/terminal/Git.
- `core/media` — media capabilities and transformations.
- `core/workspace` — project/workspace indexing, code intelligence, safe editing and verification.
- `core/tasks` — queues, workers, scheduling and workflows.
- `core/security` — identity, permissions, policy enforcement, secrets, sandboxing and audit. Security is cross-cutting and must not depend on the subsystem it protects.
- `core/api` — external API surface.
- `core/system` — maintenance, migrations, backup and recovery.

## Dependency direction

Preferred direction:

```text
                    00-platform
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
     10-agentic      70-tasks          90-api
        │
        ▼
   capability/tool boundary
        │
   ┌────┼───────────┬───────────┐
   ▼    ▼           ▼           ▼
Linux Workspace  Connectors    Media
   │       │           │
   └───────┴───────────┴───────┘
              │
              ▼
            Storage

80-security is a cross-cutting enforcement boundary. Other subsystems may depend on security policy; security must not depend on Linux, connectors, media, workspace, or Agentic implementation details.
```

## Hard rules

1. Agentic Core must not call provider APIs directly except through model adapters.
2. Agentic Core must not call GitHub/Replit/Google APIs directly. Those belong to connectors.
3. Agentic Core must request capabilities; policy decides whether execution is allowed.
4. Connectors expose capabilities and remote operations; synchronization state belongs to `core/sync`.
5. `core/sync` is independent of Agentic. Human edits are first-class changes.
6. `core/linux` owns local OS execution. `core/security` owns the policy that decides whether an OS operation is permitted.
7. `core/workspace` may use OS adapters, but must not own external-provider authentication.
8. Persistent user data must not be stored inside source directories under source directories.
9. Runtime state must not be treated as source code.
10. Historical milestone checkers are tests/regression artifacts, not production architecture.

## Agent authority model

```text
Agent intent
    ↓
Capability request
    ↓
Security policy / permission
    ↓
Approval when required
    ↓
Subsystem executor / connector
    ↓
Observation + audit
    ↓
Agent continues or replans
```

The Agent never receives unrestricted authority merely because it selected a tool.

## Sync model

```text
External provider ── Connector ──┐
                                 ├── Sync Engine ── Workspace
Human edits ─────────────────────┤
Agent edits ─────────────────────┘
```

The sync engine compares base/local/remote state, records snapshots, detects conflicts and chooses or requests reconciliation. It is not a synonym for a GitHub API wrapper.
