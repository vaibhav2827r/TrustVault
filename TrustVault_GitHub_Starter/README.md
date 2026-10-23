# TrustVault — Secure Document Sharing Prototype

TrustVault is a learning/hiring-project prototype for a multi-tenant document-sharing platform. It demonstrates a small dashboard, demo identities, document metadata, sharing permissions, and an audit-event view.

> **Security notice:** This repository currently contains a demo, not a production-secure document management system. The demo uses in-memory data, has no real authentication, does not store uploaded file contents, and is not a tamper-proof audit system. Do not use real or sensitive documents or deploy it publicly as-is.

## Features in this prototype

- Browser dashboard served locally
- Demo organization and user identities
- Document metadata creation and listing
- Basic share-permission workflow
- Audit-event display
- JavaScript (Node.js built-in modules) and Python (standard library) versions

The `.js` and `.py` files are alternative implementations. Run one at a time because both use port `3000` by default.

## Requirements

- Node.js 18+ for the JavaScript version
- Python 3.9+ for the Python version
- No third-party packages are required for the demo

## Run the JavaScript version

```bash
node trustvault.js
```

Then open http://localhost:3000 in your browser.

## Run the Python version

```bash
python trustvault.py
```

Then open http://localhost:3000 in your browser.

Stop the server with `Ctrl+C`.

## Demo checklist

1. Open the dashboard.
2. Inspect the demo organization and user selector.
3. Create document metadata (this does not upload a real file).
4. Try the share action with one of the demo user IDs shown in the interface.
5. Inspect the audit trail.
6. Switch demo identities and observe the prototype's access behavior.

## Project structure

```text
TrustVault/
├── trustvault.js
├── trustvault.py
├── README.md
├── LICENSE
├── .gitignore
├── package.json
├── docs/
│   ├── DEMO_TEST_CHECKLIST.md
│   └── PROJECT_PLAN.md
└── .github/
    └── workflows/
        └── ci.yml
```

## Planned production architecture

A production implementation should use:
- A frontend such as Next.js
- Supabase Auth or another trusted identity provider
- PostgreSQL with Row Level Security (RLS) for tenant-scoped data access
- Private object storage and short-lived signed URLs
- Server-side authorization checks for every operation
- Persistent, append-only audit records with appropriate access controls
- File type/size validation, malware scanning where appropriate, rate limiting, secure headers, and automated tests

The current demo does **not** implement these production controls. Review `docs/PROJECT_PLAN.md` before extending it.

## GitHub

Create a repository named `TrustVault`, then upload/commit the contents of this folder. Do not commit secrets, credentials, real documents, or `.bak` backup files.
