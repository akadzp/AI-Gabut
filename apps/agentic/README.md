# Agentic V3 Runtime

Start with:

```bash
AGENTIC_CREDENTIAL_KEY="a-long-secret" npm run start:agentic
```

Default host/port: `127.0.0.1:3100`.

This batch establishes the application boundary, authentication, durable
user-owned sessions, encrypted provider credentials, GitHub read context,
workspace records, Agent Engine integration, and the first frontend shell.

GitHub writes are intentionally not exposed yet. The provider mutation flow
will be added only after it is connected to the existing governance/approval
path.
