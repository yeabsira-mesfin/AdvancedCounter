# Traceguard: engineering decisions

## Why a self-contained demo

A recruiter can run the application without a paid API account or external database. FastAPI owns authentication and policy enforcement; React renders typed API responses; SQLite provides transactions and queryable evidence. Model capabilities are optional and cannot extend application permissions.

## Identity and resource boundaries

Users authenticate with scrypt-hashed passwords. The browser receives a random opaque cookie; the database stores only its digest. Sessions expire after one hour and are revoked on logout or rotation. Tenant and role come from the server session rather than client parameters. Mutating requests require a same-origin custom header; only explicitly allowed origins pass.

## Evidence over claims

The planner is deterministic and limited to `get_asset`, `search_logs`, and `lookup_indicator`; it is not an autonomous model-selected tool loop. Only structured login events determine severity. Optional Ollama generation summarizes filtered evidence without gaining action authority.

Containment changes a local proposal record only. There is no live SIEM, EDR, shell execution, or actual endpoint isolation. Approval requires a different user with the administrator role, checks tenant ownership inside a transaction, and rejects a second approval.

The fixed three-step plan and ten-second read-tool budget limit execution. The optional model has a separate 45-second timeout. These are synthetic demonstrations, not measured operational response improvements.

## Next engineering milestones

1. Move identity to OIDC with MFA and unique user provisioning.
2. Migrate the store to PostgreSQL with migrations and database-level tenant policies.
3. Add model-specific evaluation datasets and independent human review of generated answers.
4. Move ingestion and long jobs to durable workers with retries and idempotency keys.
5. Add structured observability, load tests, and production retention controls.

These milestones are not implemented. Describe only completed functionality when discussing the project in applications.
