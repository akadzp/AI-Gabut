# Backend Architecture — v2 Boundary Contract

This backend is a modular personal-AI platform. `10-agentic` is the agent's logic/behavior, not the owner of the entire system.

## Top-level boundaries

- `00-platform` — bootstrap, configuration, lifecycle, events, registries, diagnostics and system composition.
- `10-agentic` — reasoning, planning, goals, context/memory, model routing, agent tool selection, evaluation and agent reliability.
- `20-connectors` — adapters to external systems and provider APIs. A connector does not become the Agent's memory or reasoning layer.
- `30-storage` — storage abstractions and implementations. Persistent data lives outside `backend/`.
- `35-sync` — synchronization/reconciliation between local workspace state and external systems. It must support changes made by both humans and agents.
- `40-linux` — operating-system capabilities: filesystem/process/package/service/system/terminal/Git.
- `50-media` — media capabilities and transformations.
- `60-workspace` — project/workspace indexing, code intelligence, safe editing and verification.
- `70-tasks` — queues, workers, scheduling and workflows.
- `80-security` — identity, permissions, policy enforcement, secrets, sandboxing and audit. Security is cross-cutting and must not depend on the subsystem it protects.
- `90-api` — external API surface.
- `99-system` — maintenance, migrations, backup and recovery.

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
4. Connectors expose capabilities and remote operations; synchronization state belongs to `35-sync`.
5. `35-sync` is independent of Agentic. Human edits are first-class changes.
6. `40-linux` owns local OS execution. `80-security` owns the policy that decides whether an OS operation is permitted.
7. `60-workspace` may use OS adapters, but must not own external-provider authentication.
8. Persistent user data must not be stored inside source directories under `backend/`.
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
