# TrustVault Project Plan

## Goal

Build a secure, multi-tenant document-sharing application with role-based access control and an auditable record of important actions.

## Current prototype

- Local dashboard and demo API
- Demo identities and organization examples
- Document metadata rather than actual file storage
- Basic share workflow
- In-memory audit-event list

## Recommended implementation stages

### Stage 1 — Establish the baseline
- Run both versions locally and compare behavior.
- Add screenshots and a short demo script to the repository.
- Keep the demo clearly labeled as non-production.

### Stage 2 — Add real identity
- Use a trusted authentication provider such as Supabase Auth.
- Remove query-string/user-selector identity as an authorization mechanism.
- Derive the acting user from the verified server-side session.

### Stage 3 — Persistent database and tenant boundaries
- Model organizations, memberships, documents, shares, and audit events.
- Enforce organization boundaries in database policies (for example, PostgreSQL Row Level Security).
- Test that users cannot read or modify another tenant's records by guessing IDs.

### Stage 4 — Private file storage
- Upload files to private object storage.
- Validate file size and allowed content types on the server.
- Authorize every download and use short-lived signed URLs where appropriate.
- Never expose a public bucket for confidential documents.

### Stage 5 — Reliable authorization and auditing
- Enforce roles on the server for every read, create, share, update, and revoke action.
- Log actor, action, target, timestamp, outcome, and relevant request metadata without recording secrets.
- Restrict audit-log modification and test access to audit records.
- Treat audit logs as security-sensitive data; a simple in-memory list is not tamper-proof.

### Stage 6 — Quality and deployment
- Add automated unit and integration tests.
- Add rate limiting, secure headers, error handling, monitoring, and backup/restore procedures.
- Store credentials in deployment secrets, never in source code.
- Deploy only after a security review and end-to-end tests.

## Suggested acceptance criteria

- A user can only access organizations they belong to.
- Roles and sharing permissions are enforced server-side.
- Revoked access no longer grants access to the document.
- Files remain private unless a valid authorization check succeeds.
- Critical actions create audit records.
- Automated tests cover cross-tenant access denial and permission revocation.
