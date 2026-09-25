# Security and Authority

This subsystem owns identity, permissions, policy enforcement, secrets, sandboxing and audit.

Security is a cross-cutting boundary. It may inspect or authorize operations from other subsystems, but it must not depend on their implementation details.

In particular, OS command policy lives under `80-security/policies/`, while command execution remains under `40-linux/terminal/`.

## Authority flow

```text
Agent → capability request → Security → executor/connector → audit
```
